// utils/crypto-utils.js
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Generate or load RSA key pair
const privateKeyPath = path.join(__dirname, '../keys/private.pem');
const publicKeyPath = path.join(__dirname, '../keys/public.pem');

if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  fs.writeFileSync(privateKeyPath, privateKey.export({ type: 'pkcs1', format: 'pem' }));
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'pkcs1', format: 'pem' }));
}

const privateKey = fs.readFileSync(privateKeyPath, 'utf-8');
const publicKey = fs.readFileSync(publicKeyPath, 'utf-8');

function signData(dataBuffer) {
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(dataBuffer);
  sign.end();
  return sign.sign(privateKey).toString('base64');
}

function verifySignature(dataBuffer, signature) {
  const verify = crypto.createVerify('RSA-SHA256');
  verify.update(dataBuffer);
  verify.end();
  return verify.verify(publicKey, Buffer.from(signature, 'base64'));
}

module.exports = {
  signData,
  verifySignature,
  publicKey,
};
