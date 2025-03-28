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

    // Use EdDSA with Curve25519 for signing
    static sign(privateKey, data) {
        const sign = crypto.createSign('eddsa');
        sign.update(data);
        sign.end();
        return sign.sign(privateKey);
    }

    // Verify EdDSA with Curve25519 signature
    static verify(publicKey, data, signature) {
        const verify = crypto.createVerify('eddsa');
        verify.update(data);
        verify.end();
        return verify.verify(publicKey, signature);
    }

    // Create a new EdDSA private key (Curve25519)
    static createPrivateKey() {
        return crypto.generateKeyPairSync('eddsa', { namedCurve: 'x25519' }).privateKey;
    }

    // Derive EdDSA public key from private key (Curve25519)
    static createPublicKey(privateKey) {
        return crypto.createPublicKey(privateKey);
    }

    // Create HMAC with SHA-256
    static createHmac(key, data) {
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(data);
        return hmac.digest();
    }

    // Apply HMAC with SHA-256
    static applyHmac(key, data) {
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(data);
        return hmac.digest('hex');
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
