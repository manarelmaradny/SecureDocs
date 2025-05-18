const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Load your private key once (adjust the path)
const privateKey = fs.readFileSync(path.join(__dirname, '..', 'keys', 'private.pem'), 'utf8');

// Load your public key once (adjust the path)
const publicKey = fs.readFileSync(path.join(__dirname, '..', 'keys', 'public.pem'), 'utf8');

function signData(buffer) {
  const signer = crypto.createSign('sha256');
  signer.update(buffer);
  signer.end();
  const signature = signer.sign(privateKey);
  return signature.toString('base64');
}

function verifySignature(buffer, signatureBase64) {
  const verifier = crypto.createVerify('sha256');
  verifier.update(buffer);
  verifier.end();
  const signature = Buffer.from(signatureBase64, 'base64');
  return verifier.verify(publicKey, signature);
}

module.exports = { signData, verifySignature };
