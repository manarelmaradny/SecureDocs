const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const passport = require('passport');
const { PrismaClient } = require('@prisma/client');
const rateLimit = require('express-rate-limit');

const prisma = new PrismaClient();
const router = express.Router();
const SALT_ROUNDS = 10;

const oktaLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, try again in 5 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Validation functions
function isValidEmail(email) {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
}

function isValidPassword(password) {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{9,}$/;
  return regex.test(password);
}

// GET login page
router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'login.html'));
});

// GET signup page
router.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'signup.html'));
});

// POST signup
router.post('/signup', async (req, res) => {
  const { email, password, name } = req.body;

  if (!isValidEmail(email)) {
    return res.sendFile(path.join(__dirname, '../public', 'signup.html'), { error: 'Invalid email format.' });
  }

  if (!isValidPassword(password)) {
    return res.sendFile(path.join(__dirname, '../public', 'signup.html'), {
      error: 'Password must be at least 9 characters long, with uppercase, lowercase, number, and special character.'
    });
  }

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return res.sendFile(path.join(__dirname, '../public', 'signup.html'), { error: 'User already exists.' });
  }

  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  await prisma.user.create({
    data: { email, name, password: hashedPassword, role: 'USER' }
  });

  res.redirect('/login');
});

// POST login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!isValidEmail(email)) {
    return res.sendFile(path.join(__dirname, '../public', 'login.html'), { error: 'Invalid email format.' });
  }

  if (!isValidPassword(password)) {
    return res.sendFile(path.join(__dirname, '../public', 'login.html'), { error: 'Password must be at least 9 characters long, with uppercase, lowercase, number, and special character.' });
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !user.password) {
    return res.sendFile(path.join(__dirname, '../public', 'login.html'), { error: 'Invalid credentials.' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.sendFile(path.join(__dirname, '../public', 'login.html'), { error: 'Invalid credentials.' });
  }

  if (user.is2FAEnabled) {
    req.session.pending2FA = user.id;
    return res.redirect('/2fa/verify-login');
  }

  req.login(user, (err) => {
    if (err) return res.sendFile(path.join(__dirname, '../public', 'login.html'), { error: 'Login failed.' });
    res.redirect('/dashboard');
  });
});

// OAuth - Okta
router.get('/auth/okta', oktaLimiter, passport.authenticate('okta'));
router.get('/auth/okta/callback', (req, res, next) => {
  passport.authenticate('okta', (err, user) => {
    if (err || !user) return res.redirect('/');
    req.login(user, (err) => {
      if (err) return next(err);
      res.redirect('/dashboard');
    });
  })(req, res, next);
});

// OAuth - Google
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/auth/google/callback', passport.authenticate('google', {
  successRedirect: '/dashboard',
  failureRedirect: '/'
}));

// OAuth - GitHub
router.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
router.get('/auth/github/callback', passport.authenticate('github', {
  successRedirect: '/dashboard',
  failureRedirect: '/'
}));

module.exports = router;
