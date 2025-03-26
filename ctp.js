const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

function generateECDHKey() {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.generateKeys();
    const privateKey = ecdh.getPrivateKey();
    const publicKey = ecdh.getPublicKey(null, 'compressed'); // 33-byte public key
    return { privateKey, publicKey };
}

// Compute shared secret from private key and peer public key
function ecdhSharedSecret(privateKey, peerPublicKey) {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(privateKey);
    const sharedSecret = ecdh.computeSecret(peerPublicKey);
    return crypto.createHash('sha256').update(sharedSecret).digest(); // Derive a fixed 32-byte key
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

// File Compression using zlib
function compressFile(inputFilePath, outputFilePath) {
    const input = fs.createReadStream(inputFilePath);
    const output = fs.createWriteStream(outputFilePath);
    const gzip = zlib.createDeflate();
    input.pipe(gzip).pipe(output);
}

// File Decompression using zlib
function decompressFile(inputFilePath, outputFilePath) {
    const input = fs.createReadStream(inputFilePath);
    const output = fs.createWriteStream(outputFilePath);
    const gunzip = zlib.createInflate();
    input.pipe(gunzip).pipe(output);
}

// Encrypt a file using AES-256-GCM
function encryptFile(key, inputFilePath, outputFilePath, associatedData = null) {
    const input = fs.readFileSync(inputFilePath);
    const encryptedData = aes256GcmEncrypt(key, input, associatedData);
    fs.writeFileSync(outputFilePath, encryptedData);
}

// Decrypt a file using AES-256-GCM
function decryptFile(key, inputFilePath, outputFilePath, associatedData = null) {
    const encryptedData = fs.readFileSync(inputFilePath);
    const decryptedData = aes256GcmDecrypt(key, encryptedData, associatedData);
    fs.writeFileSync(outputFilePath, decryptedData);
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

    encryptFile(key, inputFilePath, outputFilePath, associatedData = null) {
        encryptFile(key, inputFilePath, outputFilePath, associatedData);
    }

    decryptFile(key, inputFilePath, outputFilePath, associatedData = null) {
        decryptFile(key, inputFilePath, outputFilePath, associatedData);
    }

    compressFile(inputFilePath, outputFilePath) {
        compressFile(inputFilePath, outputFilePath);
    }

    decompressFile(inputFilePath, outputFilePath) {
        decompressFile(inputFilePath, outputFilePath);
    }
}

module.exports = CustomProtocol;
