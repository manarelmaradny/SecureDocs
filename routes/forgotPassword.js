const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// POST /forgot-password — Update password if email exists
router.post('/forgot-password', async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).send('Email and new password are required.');
  }

  try {
    // 1. Check if user exists
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(400).send(`
  <html>
    <head>
      <title>Email Not Found Error</title>
      <style>
        body {
          background-color: #0a192f;
          color: #ff5555;
          font-family: 'Space Mono', monospace;
          text-align: center;
          padding: 50px;
        }
        a {
          color: #8be9fd;
          text-decoration: none;
          font-weight: bold;
        }
        a:hover {
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <h2>Email not found.</h2>
      <p><a href="/forgot-password.html">Go back to reset password</a></p>
    </body>
  </html>
`);
    }

    // 2. Check if new password is same as the old one
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
return res.status(400).send(`
  <html>
    <head>
      <title>Password Reset Error</title>
      <style>
        body {
          background-color: #0a192f;
          color: #ff5555;
          font-family: 'Space Mono', monospace;
          text-align: center;
          padding: 50px;
        }
        a {
          color: #8be9fd;
          text-decoration: none;
          font-weight: bold;
        }
        a:hover {
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <h2>New password cannot be the same as the old password.</h2>
      <p><a href="/forgot-password.html">Go back to reset password</a></p>
    </body>
  </html>
`);
    }

    // 3. Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 4. Update password
    await prisma.user.update({
      where: { email },
      data: { password: hashedPassword },
    });

    // 5. Redirect to login
    res.redirect('/login'); // Adjust the path if your login page is different
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).send('Internal Server Error');
  }
});

module.exports = router;
