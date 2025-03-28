const crypto = require('crypto');
const zlib = require('zlib');

class KeyHelper {
    static generateECDHKey() {
        const ecdh = crypto.createECDH('secp256k1');
        ecdh.generateKeys();
        return {
            privateKey: ecdh.getPrivateKey(),
            publicKey: ecdh.getPublicKey(null, 'compressed') // 33-byte public key
        };
    }

    static ecdhSharedSecret(privateKey, peerPublicKey) {
        const ecdh = crypto.createECDH('secp256k1');
        ecdh.setPrivateKey(privateKey);
        return ecdh.computeSecret(peerPublicKey);
    }

    static hkdf(secret, salt = '', info = '', length = 32) {
        return crypto.hkdfSync('sha256', secret, salt, info, length);
    }

    static compressData(data) {
        return zlib.deflateSync(data);
    }

    static decompressData(data) {
        return zlib.inflateSync(data);
    }
}

class CTProtoStore {
    constructor() {
        this.store = {};
    }

    storeIdentityKeyPair(identityKeyPair) {
        this.store.identityKeyPair = identityKeyPair;
    }

    storePreKey(preKeyId, preKey) {
        if (!this.store.preKeys) this.store.preKeys = {};
        this.store.preKeys[preKeyId] = preKey;
    }

    storeSignedPreKey(signedPreKeyId, signedPreKey) {
        if (!this.store.signedPreKeys) this.store.signedPreKeys = {};
        this.store.signedPreKeys[signedPreKeyId] = signedPreKey;
    }

    storeSession(address, session) {
        if (!this.store.sessions) this.store.sessions = {};
        this.store.sessions[address] = session;
    }

    getIdentityKeyPair() {
        return this.store.identityKeyPair;
    }

    getPreKey(preKeyId) {
        return this.store.preKeys ? this.store.preKeys[preKeyId] : null;
    }

    getSignedPreKey(signedPreKeyId) {
        return this.store.signedPreKeys ? this.store.signedPreKeys[signedPreKeyId] : null;
    }

    getSession(address) {
        return this.store.sessions ? this.store.sessions[address] : null;
    }
}

class CustomProtocol {
    constructor() {
        this.store = new CTProtoStore();
    }

    generateIdentityKeyPair() {
        return KeyHelper.generateECDHKey();
    }

    generatePreKey(preKeyId) {
        return KeyHelper.generateECDHKey();
    }

    generateSignedPreKey(signedPreKeyId) {
        const { privateKey, publicKey } = KeyHelper.generateECDHKey();
        return { privateKey, publicKey };
    }

    generateRegistrationId() {
        return crypto.randomBytes(16).toString('hex');
    }

    encrypt(key, data, associatedData = null) {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        if (associatedData) cipher.setAAD(associatedData);

        let ciphertext = cipher.update(data);
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);
        return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
    }

    decrypt(key, ciphertext, associatedData = null) {
        const iv = ciphertext.slice(0, 12);
        const tag = ciphertext.slice(12, 28);
        const data = ciphertext.slice(28);

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        if (associatedData) decipher.setAAD(associatedData);

        let plaintext = decipher.update(data);
        return Buffer.concat([plaintext, decipher.final()]);
    }

    initiateKeyExchange(privateKey, peerPublicKey) {
        return KeyHelper.ecdhSharedSecret(privateKey, peerPublicKey);
    }
}

module.exports = { CustomProtocol, KeyHelper, CTProtoStore };
