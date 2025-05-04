// SecureCommLib.js

const crypto = require('crypto');
const zlib = require('zlib');

class SecureComm {
  constructor() {
    this.dh = crypto.createDiffieHellman(2048);
    this.dh.generateKeys();
  }

  // ---- Diffie-Hellman Key Exchange ----
  getPublicKey() {
    return this.dh.getPublicKey('base64');
  }

  getSignedPublicKey() {
    const pubKey = this.getPublicKey();
    const signature = this.signData(pubKey);
    return JSON.stringify({ publicKey: pubKey, signature });
  }

  verifyPeerPublicKey(signedPayload, peerRSAPublicKey) {
    const { publicKey, signature } = JSON.parse(signedPayload);
    const isValid = this.verifySignature(publicKey, signature, peerRSAPublicKey);
    if (!isValid) throw new Error('RSA signature verification failed. Possible MITM.');
    return publicKey;
  }

  getPrime() {
    return this.dh.getPrime('base64');
  }

  getGenerator() {
    return this.dh.getGenerator('base64');
  }

  generateSharedSecret(peerPublicKey) {
    const peerKey = Buffer.from(peerPublicKey, 'base64');
    this.sharedSecret = this.dh.computeSecret(peerKey);

    const hash = crypto.createHash('sha512').update(this.sharedSecret).digest();
    this.aesKey = hash.slice(0, 32); // AES-256

    this.sharedSecret.fill(0); // Zeroize
  }

  // ---- RSA Key Pair Handling ----
  setRSAKeys(publicKey, privateKey) {
    try {
      crypto.createPublicKey(publicKey);
      crypto.createPrivateKey(privateKey);
      this.rsaKeys = { publicKey, privateKey };
    } catch {
      throw new Error('Invalid RSA key format.');
    }
  }

  // ---- Encryption ----
  encryptMessage(plainText) {
    const iv = crypto.randomBytes(12);
    const compressed = zlib.deflateSync(plainText);

    const cipher = crypto.createCipheriv('aes-256-gcm', this.aesKey, iv);
    const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const payload = {
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };

    return Buffer.from(JSON.stringify(payload)).toString('base64');
  }

  // ---- Decryption ----
  decryptMessage(base64Payload) {
    const payloadJson = Buffer.from(base64Payload, 'base64').toString();
    const { iv, authTag, ciphertext } = JSON.parse(payloadJson);

    const ivBuf = Buffer.from(iv, 'base64');
    const tagBuf = Buffer.from(authTag, 'base64');
    const ciphertextBuf = Buffer.from(ciphertext, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.aesKey, ivBuf);
    decipher.setAuthTag(tagBuf);
    const decrypted = Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]);

    return zlib.inflateSync(decrypted).toString();
  }

  // ---- RSA Digital Signature ----
  signData(data) {
    const signer = crypto.createSign('SHA256');
    signer.update(data);
    signer.end();
    return signer.sign(this.rsaKeys.privateKey, 'base64');
  }

  verifySignature(data, signature, publicKey) {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(data);
    verifier.end();
    return verifier.verify(publicKey, signature, 'base64');
  }

  // ---- Static Utilities ----
  static generateRSAKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
  }
}

module.exports = SecureComm;
