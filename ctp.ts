// SecureCommLib.ts

import * as crypto from 'crypto';
import * as zlib from 'zlib';

type RSAPair = {
  publicKey: string;
  privateKey: string;
};

type EncryptedPayload = {
  iv: string;
  authTag: string;
  ciphertext: string;
};

export class SecureComm {
  private aesKey: Buffer;
  private dh: crypto.DiffieHellman;
  private sharedSecret: Buffer;
  private rsaKeys: RSAPair;

  constructor() {
    this.dh = crypto.createDiffieHellman(2048);
    this.dh.generateKeys();
  }

  // ---- Diffie-Hellman Key Exchange ----
  getPublicKey(): string {
    return this.dh.getPublicKey('base64');
  }

  getSignedPublicKey(): string {
    const pubKey = this.getPublicKey();
    const signature = this.signData(pubKey);
    return JSON.stringify({ publicKey: pubKey, signature });
  }

  verifyPeerPublicKey(signedPayload: string, peerRSAPublicKey: string): string {
    const { publicKey, signature } = JSON.parse(signedPayload);
    const isValid = this.verifySignature(publicKey, signature, peerRSAPublicKey);
    if (!isValid) throw new Error('RSA signature verification failed. Possible MITM.');
    return publicKey;
  }

  getPrime(): string {
    return this.dh.getPrime('base64');
  }

  getGenerator(): string {
    return this.dh.getGenerator('base64');
  }

  generateSharedSecret(peerPublicKey: string): void {
    const peerKey = Buffer.from(peerPublicKey, 'base64');
    this.sharedSecret = this.dh.computeSecret(peerKey);

    const hash = crypto.createHash('sha512').update(this.sharedSecret).digest();
    this.aesKey = hash.slice(0, 32); // AES-256

    this.sharedSecret.fill(0); // Zeroize
  }

  // ---- RSA Key Pair Handling ----
  setRSAKeys(publicKey: string, privateKey: string): void {
    try {
      crypto.createPublicKey(publicKey);
      crypto.createPrivateKey(privateKey);
      this.rsaKeys = { publicKey, privateKey };
    } catch {
      throw new Error('Invalid RSA key format.');
    }
  }

  // ---- Encryption ----
  encryptMessage(plainText: string): string {
    const iv = crypto.randomBytes(12);
    const compressed = zlib.deflateSync(plainText);

    const cipher = crypto.createCipheriv('aes-256-gcm', this.aesKey, iv);
    const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const payload: EncryptedPayload = {
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };

    return Buffer.from(JSON.stringify(payload)).toString('base64');
  }

  // ---- Decryption ----
  decryptMessage(base64Payload: string): string {
    const payloadJson = Buffer.from(base64Payload, 'base64').toString();
    const { iv, authTag, ciphertext }: EncryptedPayload = JSON.parse(payloadJson);

    const ivBuf = Buffer.from(iv, 'base64');
    const tagBuf = Buffer.from(authTag, 'base64');
    const ciphertextBuf = Buffer.from(ciphertext, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.aesKey, ivBuf);
    decipher.setAuthTag(tagBuf);
    const decrypted = Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]);

    return zlib.inflateSync(decrypted).toString();
  }

  // ---- RSA Digital Signature ----
  signData(data: string): string {
    const signer = crypto.createSign('SHA256');
    signer.update(data);
    signer.end();
    return signer.sign(this.rsaKeys.privateKey, 'base64');
  }

  verifySignature(data: string, signature: string, publicKey: string): boolean {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(data);
    verifier.end();
    return verifier.verify(publicKey, signature, 'base64');
  }

  // ---- Static Utilities ----
  static generateRSAKeyPair(): RSAPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
  }
}
