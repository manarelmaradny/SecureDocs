const path = require('path');
const fs = require('fs');
const express = require('express');
const crypto = require('crypto');
const { PrismaClient } = require('@prisma/client');
const { requireRole } = require('../middleware/roles');
const { verifySignature } = require('../utils/crypto');

const prisma = new PrismaClient();
const router = express.Router();

async function logAction(userId, action, ip) {
  try {
    await prisma.log.create({
      data: {
        userId,
        action,
        ipAddress: ip || 'unknown'
      }
    });
  } catch (e) {
    console.error('Failed to log action:', e);
  }
}

// Dashboard
router.get('/dashboard', async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  await logAction(req.user.id, 'VIEW_DASHBOARD', req.ip);

  const html = fs.readFileSync(path.join(__dirname, '../public/dashboard.html'), 'utf-8');

  const documents = await prisma.document.findMany({
    where: { ownerId: req.user.id }
  });

  const documentRows = documents.map(doc => `
    <tr>
      <td>${doc.title}</td>
      <td>${doc.filename}</td>
      <td><a href="/${doc.filePath}" target="_blank">View</a></td>
      <td>
        <a href="/dashboard/edit/${doc.id}" class="btn btn-sm btn-warning">Edit</a>
        <a href="/dashboard/download/${doc.id}" class="btn btn-sm btn-primary">Download</a>
        <a href="/dashboard/verify/${doc.id}" class="btn btn-sm btn-info">Verify</a>
        <form method="POST" action="/dashboard/delete/${doc.id}" class="d-inline">
          <button type="submit" class="btn btn-sm btn-danger">Delete</button>
        </form>
      </td>
    </tr>
  `).join('');

  const output = html
    .replace('{{name}}', req.user.name)
    .replace('{{role}}', req.user.role)
    .replace('{{adminLink}}', req.user.role === 'ADMIN'
      ? '<a class="btn btn-warning me-2" href="/admin">Admin Panel</a>'
      : '')
    .replace('{{documentRows}}', documentRows);

  res.send(output);
});

// Admin Panel
router.get('/admin', requireRole('ADMIN'), async (req, res) => {
  await logAction(req.user.id, 'VIEW_ADMIN_PANEL', req.ip);

  const html = fs.readFileSync(path.join(__dirname, '../public/admin.html'), 'utf-8');
  const users = await prisma.user.findMany({ select: { id: true, name: true, email: true, role: true } });
  const logs = await prisma.log.findMany({
    include: { user: true },
    orderBy: { timestamp: 'desc' },
    take: 50 // Limit the logs shown for performance
  });

  const userRows = users.map(user => {
    const isAdmin = user.role === 'ADMIN';
    const toggle = isAdmin ? 'USER' : 'ADMIN';
    const label = isAdmin ? 'Demote' : 'Promote';
    const button = user.id === req.user.id
      ? '<em>(You)</em>'
      : `
        <form method="POST" action="/admin/role" class="d-inline">
          <input type="hidden" name="userId" value="${user.id}" />
          <input type="hidden" name="newRole" value="${toggle}" />
          <button type="submit" class="btn btn-sm btn-${toggle === 'ADMIN' ? 'success' : 'secondary'}">${label}</button>
        </form>
        <form method="POST" action="/admin/delete/${user.id}" class="d-inline">
          <button type="submit" class="btn btn-sm btn-danger">Delete</button>
        </form>
      `;

    return `
      <tr>
        <td>${user.name}</td>
        <td>${user.email}</td>
        <td><span class="badge bg-${user.role === 'ADMIN' ? 'warning' : 'secondary'}">${user.role}</span></td>
        <td>${button}</td>
      </tr>
    `;
  }).join('');

  const logRows = logs.map(log => `
    <tr>
      <td>${log.user ? log.user.name : 'Unknown'}</td>
      <td>${log.action}</td>
      <td>${log.ipAddress}</td>
      <td>${new Date(log.timestamp).toLocaleString()}</td>
    </tr>
  `).join('');

  // Replace both placeholders in your admin.html
  const output = html
    .replace('{{userRows}}', userRows)
    .replace('{{logRows}}', logRows);

  res.send(output);
});


// Admin Actions
router.post('/admin/role', requireRole('ADMIN'), async (req, res) => {
  const { userId, newRole } = req.body;
  if (!['USER', 'ADMIN'].includes(newRole)) return res.status(400).send('Invalid role.');
  if (userId === req.user.id) return res.status(403).send("You can't change your own role.");

  await prisma.user.update({ where: { id: userId }, data: { role: newRole } });
  await logAction(req.user.id, `CHANGE_ROLE to ${newRole} for user ${userId}`, req.ip);

  res.redirect('/admin');
});

router.post('/admin/delete/:id', requireRole('ADMIN'), async (req, res) => {
  if (req.params.id === req.user.id) return res.status(403).send("You can't delete your own account.");

  await prisma.user.delete({ where: { id: req.params.id } });
  await logAction(req.user.id, `DELETE_USER ${req.params.id}`, req.ip);

  res.redirect('/admin');
});

// Edit Document
router.get('/dashboard/edit/:id', async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  const document = await prisma.document.findUnique({ where: { id: req.params.id } });
  if (!document || (document.ownerId !== req.user.id && req.user.role !== 'ADMIN')) {
    return res.status(403).send('Access denied.');
  }

  await logAction(req.user.id, `VIEW_EDIT_DOCUMENT ${req.params.id}`, req.ip);

  const html = fs.readFileSync(path.join(__dirname, '../public/edit-document.html'), 'utf-8');
  res.send(html
    .replace('{{title}}', document.title)
    .replace('{{id}}', document.id)
    .replace('{{filename}}', document.filename));
});

router.post('/dashboard/edit/:id', async (req, res) => {
  const document = await prisma.document.findUnique({ where: { id: req.params.id } });
  if (!document || (document.ownerId !== req.user.id && req.user.role !== 'ADMIN')) {
    return res.status(403).send('Access denied.');
  }

  await prisma.document.update({
    where: { id: req.params.id },
    data: { title: req.body.title }
  });

  await logAction(req.user.id, `EDIT_DOCUMENT ${req.params.id}`, req.ip);

  res.redirect('/dashboard');
});

// Delete Document
router.post('/dashboard/delete/:id', async (req, res) => {
  const document = await prisma.document.findUnique({ where: { id: req.params.id } });
  if (!document || (document.ownerId !== req.user.id && req.user.role !== 'ADMIN')) {
    return res.status(403).send('Access denied.');
  }

  await prisma.document.delete({ where: { id: req.params.id } });

  await logAction(req.user.id, `DELETE_DOCUMENT ${req.params.id}`, req.ip);

  res.redirect('/dashboard');
});

// Secure Download
router.get('/dashboard/download/:id', async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  const doc = await prisma.document.findUnique({ where: { id: req.params.id } });
  if (!doc || (doc.ownerId !== req.user.id && req.user.role !== 'ADMIN')) {
    return res.status(403).send('Access denied.');
  }

  await logAction(req.user.id, `DOWNLOAD_DOCUMENT ${req.params.id}`, req.ip);

  try {
    const encryptedBuffer = fs.readFileSync(doc.filePath);
    const encryptedKey = Buffer.from(doc.encryptedKey, 'base64');
    const aesKey = encryptedKey.slice(0, 32);
    const iv = encryptedKey.slice(32, 48);

    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);

    res.setHeader('Content-Disposition', `attachment; filename="${doc.filename}"`);
    res.setHeader('Content-Type', doc.mimeType);
    res.send(decrypted);
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).send('Failed to decrypt or download file.');
  }
});

// Integrity & Signature Verification
router.get('/dashboard/verify/:id', async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  const doc = await prisma.document.findUnique({ where: { id: req.params.id } });
  if (!doc || (doc.ownerId !== req.user.id && req.user.role !== 'ADMIN')) {
    return res.status(403).send('Access denied.');
  }

  await logAction(req.user.id, `VERIFY_DOCUMENT ${req.params.id}`, req.ip);

  try {
    const encryptedBuffer = fs.readFileSync(doc.filePath);
    const encryptedKey = Buffer.from(doc.encryptedKey, 'base64');
    const aesKey = encryptedKey.slice(0, 32);
    const iv = encryptedKey.slice(32, 48);

    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);

    const hash = crypto.createHash('sha256').update(decrypted).digest('hex');
    const hashValid = hash === doc.hash;
    const signatureValid = verifySignature(decrypted, doc.signature);

    res.send(`
      <h3>Document Verification</h3>
      <p>Hash Match: ${hashValid ? 'Yes' : 'No'}</p>
      <p>Signature Valid: ${signatureValid ? 'Yes' : 'No'}</p>
      <a href="/dashboard">⬅ Back to Dashboard</a>
    `);
  } catch (err) {
    console.error('Verification error:', err);
    res.status(500).send('Verification failed.');
  }
});

// Logout
router.get('/logout', async (req, res) => {
  if (req.isAuthenticated()) {
    await logAction(req.user.id, 'LOGOUT', req.ip);
    req.logout(() => res.redirect('/'));
  } else {
    res.redirect('/');
  }
});

module.exports = router;
