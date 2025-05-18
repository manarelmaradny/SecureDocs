const express = require('express');
const router = express.Router();
const prisma = require('../prisma-client'); // Adjust path if needed
const path = require('path');
const fs = require('fs');

// Log action helper function
async function logAction(userId, action, ip) {
  try {
    await prisma.log.create({
      data: {
        userId,
        action,
        ipAddress: ip || 'unknown',
      },
    });
  } catch (e) {
    console.error('Failed to log action:', e);
  }
}

// GET /profile
router.get('/profile', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  const user = req.user;

  try {
    const activities = await prisma.log.findMany({
      where: { userId: user.id },
      orderBy: { timestamp: 'desc' },
      take: 10,
    });

    const html = fs.readFileSync(path.join(__dirname, '../public/profile.html'), 'utf-8');

    // Generate activity rows
    const activityRows = activities.length > 0
      ? activities.map(activity => `
          <tr>
            <td>${activity.action}</td>
            <td>${new Date(activity.timestamp).toLocaleString()}</td>
          </tr>
        `).join('')
      : '';

    const noActivityMessage = activities.length === 0 ? 'No recent activity available.' : '';

    const output = html
      .replace('{{name}}', user.name)
      .replace('{{name}}', user.name) // Second occurrence in the form
      .replace('{{role}}', user.role)
      .replace('{{email}}', user.email)
      .replace('{{email}}', user.email) // Second occurrence in the form
      .replace('{{avatar}}', user.avatar || '/images/avatar.png')
      .replace('{{activityRows}}', activityRows)
      .replace('{{noActivityMessage}}', noActivityMessage);

    res.send(output);
  } catch (error) {
    console.error('Error fetching user activities:', error);

    const html = fs.readFileSync(path.join(__dirname, '../public/profile.html'), 'utf-8');

    const output = html
      .replace('{{name}}', user.name)
      .replace('{{name}}', user.name) // Second occurrence in the form
      .replace('{{role}}', user.role)
      .replace('{{email}}', user.email)
      .replace('{{email}}', user.email) // Second occurrence in the form
      .replace('{{avatar}}', user.avatar || '/images/avatar.png')
      .replace('{{activityRows}}', '')
      .replace('{{noActivityMessage}}', 'No recent activity available.');

    res.send(output);
  }
});

// POST /profile/update
router.post('/profile/update', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  const userId = req.user.id;
  const { name, email } = req.body;

  try {
    await prisma.user.update({
      where: { id: userId },
      data: { name, email },
    });

    await logAction(userId, 'UPDATE_PROFILE', req.ip);

    res.redirect('/profile');
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).send('Profile update failed.');
  }
});

module.exports = router;