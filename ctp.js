const crypto = require('crypto');
const zlib = require('zlib');

// ECDH (Elliptic Curve Diffie-Hellman) Key Generation
function generateECDHKey() {
    const ecdh = crypto.createECDH('secp256k1'); // You can also use 'prime256v1' for SECP256R1
    ecdh.generateKeys();
    const privateKey = ecdh.getPrivateKey();
    const publicKey = ecdh.getPublicKey();
    return { privateKey, publicKey };
}

// Create shared secret from private key and peer's public key
function ecdhSharedSecret(privateKey, peerPublicKey) {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(privateKey);
    const sharedSecret = ecdh.computeSecret(peerPublicKey);
    return crypto.createHash('sha256').update(sharedSecret).digest();
}

// AES-256-CTR Encryption
function aes256CtrEncrypt(key, plaintext) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
    let ciphertext = cipher.update(plaintext);
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    return Buffer.concat([iv, ciphertext]);
}

// AES-256-GCM Encryption
function aes256GcmEncrypt(key, plaintext, associatedData = null) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    if (associatedData) {
        cipher.setAAD(associatedData);
    }
    let ciphertext = cipher.update(plaintext);
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, ciphertext]);
}

// AES-256-GCM Decryption
function aes256GcmDecrypt(key, ciphertext, associatedData = null) {
    const iv = ciphertext.slice(0, 12);
    const tag = ciphertext.slice(12, 28);
    const data = ciphertext.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    if (associatedData) {
        decipher.setAAD(associatedData);
    }
    let plaintext = decipher.update(data);
    plaintext = Buffer.concat([plaintext, decipher.final()]);
    return plaintext;
}

// Data Compression using zlib
function compressData(data) {
    return zlib.deflateSync(data);
}

// Data Decompression using zlib
function decompressData(data) {
    return zlib.inflateSync(data);
}

// Example of a custom protocol class using the above methods
class CustomProtocol {
    constructor() {
        const { privateKey, publicKey } = generateECDHKey();
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    keyExchange(peerPublicKey) {
        return ecdhSharedSecret(this.privateKey, peerPublicKey);
    }

    encryptData(key, data) {
        const compressedData = compressData(data);
        return aes256GcmEncrypt(key, compressedData);
    }

    decryptData(key, ciphertext) {
        const decryptedData = aes256GcmDecrypt(key, ciphertext);
        return decompressData(decryptedData);
    }
}

module.exports = CustomProtocol;
