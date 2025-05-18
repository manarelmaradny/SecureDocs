// routes/uploads.js
const express = require('express');
const { PrismaClient } = require('@prisma/client');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const { signData } = require('../utils/crypto');

const prisma = new PrismaClient();
const router = express.Router();
const upload = multer({ dest: 'uploads/' });

function encryptAES(buffer, key, iv) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([cipher.update(buffer), cipher.final()]);
}

function computeSHA256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

router.get('/upload', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login'); // optional auth check
  res.render('upload'); // render the upload form view
});

router.post('/upload', upload.single('document'), async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  const { title } = req.body;
  const file = req.file;

  if (!file) return res.status(400).send('No file uploaded.');

  try {
    const fileBuffer = fs.readFileSync(file.path);
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const encryptedBuffer = encryptAES(fileBuffer, aesKey, iv);

    fs.writeFileSync(file.path, encryptedBuffer);

    const fileHash = computeSHA256(fileBuffer);
    const signature = signData(fileBuffer);

    await prisma.document.create({
      data: {
        title,
        filename: file.originalname,
        filePath: file.path,
        mimeType: file.mimetype,
        encryptedKey: Buffer.concat([aesKey, iv]).toString('base64'),
        hash: fileHash,
        signature,
        ownerId: req.user.id
      }
    });

    // Log the upload action
    await prisma.log.create({
      data: {
        action: 'UPLOAD_DOCUMENT',
        userId: req.user.id,
        ipAddress: req.ip || req.connection.remoteAddress || 'unknown'
      }
    });

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Error during upload:', err);
    res.status(500).send('Internal Server Error');
  }
});

module.exports = router;
