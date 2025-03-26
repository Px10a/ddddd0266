const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');

// Generating ECDH keys
function generateEcdhKey() {
    const ecdh = crypto.createECDH('secp256r1');
    ecdh.generateKeys();
    return {
        privateKey: ecdh.getPrivateKey(),
        publicKey: ecdh.getPublicKey()
    };
}

// Creating shared secret using ECDH
function ecdhSharedSecret(privateKey, peerPublicKey) {
    const ecdh = crypto.createECDH('secp256r1');
    ecdh.setPrivateKey(privateKey);
    const sharedSecret = ecdh.computeSecret(peerPublicKey);
    return crypto.createHash('sha256').update(sharedSecret).digest();
}

// AES-256-CTR encryption
function aes256CtrEncrypt(key, plaintext) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
    const ciphertext = Buffer.concat([iv, cipher.update(plaintext), cipher.final()]);
    return ciphertext;
}

// AES-256-GCM encryption
function aes256GcmEncrypt(key, plaintext, associatedData = null) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    if (associatedData) {
        cipher.setAAD(associatedData);
    }
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, ciphertext]);
}

// AES-256-GCM decryption
function aes256GcmDecrypt(key, ciphertext, associatedData = null) {
    const iv = ciphertext.slice(0, 12);
    const tag = ciphertext.slice(12, 28);
    const data = ciphertext.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    if (associatedData) {
        decipher.setAAD(associatedData);
    }
    const plaintext = Buffer.concat([decipher.update(data), decipher.final()]);
    return plaintext;
}

// Data compression using zlib
function compressData(data) {
    return zlib.deflateSync(data);
}

// Data decompression using zlib
function decompressData(data) {
    return zlib.inflateSync(data);
}

// Cryptmanx class with file encryption support
class Cryptmanx {
    constructor() {
        const keys = generateEcdhKey();
        this.privateKey = keys.privateKey;
        this.publicKey = keys.publicKey;
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

    // Encrypt a file
    encryptFile(key, inputFilePath, outputFilePath) {
        const inputFile = fs.readFileSync(inputFilePath);
        const encryptedData = this.encryptData(key, inputFile);
        fs.writeFileSync(outputFilePath, encryptedData);
        console.log(`File encrypted successfully: ${outputFilePath}`);
    }

    // Decrypt a file
    decryptFile(key, inputFilePath, outputFilePath) {
        const encryptedData = fs.readFileSync(inputFilePath);
        const decryptedData = this.decryptData(key, encryptedData);
        fs.writeFileSync(outputFilePath, decryptedData);
        console.log(`File decrypted successfully: ${outputFilePath}`);
    }
}

module.exports = Cryptmanx;
