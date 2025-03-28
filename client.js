const net = require('net');
const { CustomProtocol, KeyHelper } = require('./index');

const client = new net.Socket();
const protocol = new CustomProtocol();
const clientIdentityKeyPair = protocol.generateIdentityKeyPair();

client.connect(3000, 'localhost', () => {
    console.log('Connected to server.');

    // Receive server's public key
    client.once('data', (serverPublicKey) => {
        console.log('Received server public key.');

        // Send client's public key
        client.write(clientIdentityKeyPair.publicKey);

        // Compute shared secret
        const sharedSecret = protocol.initiateKeyExchange(clientIdentityKeyPair.privateKey, serverPublicKey);
        const encryptionKey = KeyHelper.hkdf(sharedSecret);

        console.log('Shared secret established.');

        // Receive and decrypt message
        client.once('data', (encryptedMessage) => {
            console.log('Received encrypted message.');

            const decryptedMessage = protocol.decrypt(encryptionKey, encryptedMessage);
            console.log('Decrypted message:', decryptedMessage.toString());

            client.end();
        });
    });
});

client.on('close', () => console.log('Connection closed.'));
