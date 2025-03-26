import * as crypto from 'crypto';
import * as zlib from 'zlib';
import * as fs from 'fs';
import * as path from 'path';

function generateECDHKey(): { privateKey: Buffer, publicKey: Buffer } {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.generateKeys();
    const privateKey = ecdh.getPrivateKey();
    const publicKey = ecdh.getPublicKey(null, 'compressed'); // 33-byte public key
    return { privateKey, publicKey };
}

function ecdhSharedSecret(privateKey: Buffer, peerPublicKey: Buffer): Buffer {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(privateKey);
    const sharedSecret = ecdh.computeSecret(peerPublicKey);
    return crypto.createHash('sha256').update(sharedSecret).digest(); // Derive a fixed 32-byte key
}

function aes256CtrEncrypt(key: Buffer, plaintext: Buffer): Buffer {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
    let ciphertext = cipher.update(plaintext);
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    return Buffer.concat([iv, ciphertext]);
}

function aes256GcmEncrypt(key: Buffer, plaintext: Buffer, associatedData: Buffer | null = null): Buffer {
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

function aes256GcmDecrypt(key: Buffer, ciphertext: Buffer, associatedData: Buffer | null = null): Buffer {
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

function compressData(data: Buffer): Buffer {
    return zlib.deflateSync(data);
}

function decompressData(data: Buffer): Buffer {
    return zlib.inflateSync(data);
}

function compressFile(inputFilePath: string, outputFilePath: string): void {
    const input = fs.createReadStream(inputFilePath);
    const output = fs.createWriteStream(outputFilePath);
    const gzip = zlib.createDeflate();
    input.pipe(gzip).pipe(output);
}

function decompressFile(inputFilePath: string, outputFilePath: string): void {
    const input = fs.createReadStream(inputFilePath);
    const output = fs.createWriteStream(outputFilePath);
    const gunzip = zlib.createInflate();
    input.pipe(gunzip).pipe(output);
}

function encryptFile(key: Buffer, inputFilePath: string, outputFilePath: string, associatedData: Buffer | null = null): void {
    const input = fs.readFileSync(inputFilePath);
    const encryptedData = aes256GcmEncrypt(key, input, associatedData);
    fs.writeFileSync(outputFilePath, encryptedData);
}

function decryptFile(key: Buffer, inputFilePath: string, outputFilePath: string, associatedData: Buffer | null = null): void {
    const encryptedData = fs.readFileSync(inputFilePath);
    const decryptedData = aes256GcmDecrypt(key, encryptedData, associatedData);
    fs.writeFileSync(outputFilePath, decryptedData);
}

class CustomProtocol {
    private privateKey: Buffer;
    private publicKey: Buffer;

    constructor() {
        const { privateKey, publicKey } = generateECDHKey();
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    keyExchange(peerPublicKey: Buffer): Buffer {
        return ecdhSharedSecret(this.privateKey, peerPublicKey);
    }

    encryptData(key: Buffer, data: Buffer): Buffer {
        const compressedData = compressData(data);
        return aes256GcmEncrypt(key, compressedData);
    }

    decryptData(key: Buffer, ciphertext: Buffer): Buffer {
        const decryptedData = aes256GcmDecrypt(key, ciphertext);
        return decompressData(decryptedData);
    }

    encryptFile(key: Buffer, inputFilePath: string, outputFilePath: string, associatedData: Buffer | null = null): void {
        encryptFile(key, inputFilePath, outputFilePath, associatedData);
    }

    decryptFile(key: Buffer, inputFilePath: string, outputFilePath: string, associatedData: Buffer | null = null): void {
        decryptFile(key, inputFilePath, outputFilePath, associatedData);
    }

    compressFile(inputFilePath: string, outputFilePath: string): void {
        compressFile(inputFilePath, outputFilePath);
    }

    decompressFile(inputFilePath: string, outputFilePath: string): void {
        decompressFile(inputFilePath, outputFilePath);
    }
}

export default CustomProtocol;
