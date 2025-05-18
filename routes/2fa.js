const express = require('express');
const speakeasy = require('speakeasy');
const fs = require('fs');
const path = require('path');
const qrcode = require('qrcode');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const router = express.Router();

// Middleware to check if user is authenticated
function ensureAuthenticated(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }
  next();
}

// 2fa route setup (if authenticated redirect to 2fa else return to login)
router.get('/2fa/setup', ensureAuthenticated, async (req, res) => {
  try {
    // Generate secret for the user and show email in authenticator app  
    const secret = speakeasy.generateSecret({
      name: `SecureDocs (${req.user.email})`,
      length: 20
    });

    // Store the secret temporarily in the session for later use
    req.session.temp2FASecret = secret.base32;

    // Create and display the QR code 
    qrcode.toDataURL(secret.otpauth_url, (err, imageData) => {
      if (err) {
        return res.status(500).send('Error generating QR code');
      }

      const html = fs.readFileSync(path.join(__dirname, '../public/2fa-setup.html'), 'utf-8');
      const output = html.replace('{{qrcodeImage}}', imageData);
      res.send(output);
    });
  } catch (err) {
    res.status(500).send('An error occurred while setting up 2FA');
  }
});

// Confirm 2FA after setup
router.post('/2fa/verify', ensureAuthenticated, async (req, res) => {
  try {
    if (!req.session.temp2FASecret) {
      return res.redirect('/');
    }

    const valid = speakeasy.totp.verify({
      secret: req.session.temp2FASecret,
      encoding: 'base32',
      token: req.body.token,
      window: 1
    });

    if (valid) {
      await prisma.user.update({
        where: { id: req.user.id },
        data: {
          twoFASecret: req.session.temp2FASecret,
          is2FAEnabled: true
        }
      });

      delete req.session.temp2FASecret;
      res.send('<h3>2FA Enabled Successfully!</h3><a href="/dashboard">Back to Dashboard</a>');
    } else {
      res.send('<h3>Invalid Code. Try again.</h3><a href="/2fa/setup">Back</a>');
    }
  } catch (err) {
    res.status(500).send('An error occurred while verifying 2FA');
  }
});

// Login 2FA verification
router.get('/2fa/verify-login', (req, res) => {
  if (!req.session.pending2FA) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, '../public/2fa-verify.html'));
});

router.post('/2fa/verify-login', async (req, res) => {
  try {
    const userId = req.session.pending2FA;
    if (!userId) {
      return res.redirect('/');
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.twoFASecret) {
      return res.redirect('/');
    }

    const valid = speakeasy.totp.verify({
      secret: user.twoFASecret,
      encoding: 'base32',
      token: req.body.token,
      window: 1
    });

    if (!valid) {
      return res.send('<h3>Invalid Code. <a href="/2fa/verify-login">Try again</a></h3>');
    }

    req.login(user, (err) => {
      if (err) {
        return res.status(500).send('Login failed.');
      }
      delete req.session.pending2FA;
      res.redirect('/dashboard');
    });
  } catch (err) {
    res.status(500).send('An error occurred while verifying login 2FA');
  }
});

module.exports = router;
