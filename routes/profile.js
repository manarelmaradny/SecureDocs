const express = require('express');
const router = express.Router();
const prisma = require('../prisma'); // Adjust path if needed

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

    res.render('profile', {
      name: user.name,
      role: user.role,
      email: user.email,
      avatar: user.avatar || '/images/avatar.png',
      activities,
    });
  } catch (error) {
    console.error('Error fetching user activities:', error);

    res.render('profile', {
      name: user.name,
      role: user.role,
      email: user.email,
      avatar: user.avatar || '/images/avatar.png',
      activities: [],
    });
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
