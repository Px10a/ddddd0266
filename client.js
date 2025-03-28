const net = require('net');
const readline = require('readline');
const { CustomProtocol, KeyHelper } = require('./index'); // Assuming the provided code is saved in cryptoProtocol.js

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const client = new net.Socket();
const protocol = new CustomProtocol();
let clientPrivateKey, clientPublicKey, serverPublicKey, sharedSecret;

client.connect(8000, '127.0.0.1', () => {
    // Step 1: Generate client key pair and send public key to server
    const { privateKey, publicKey } = KeyHelper.generateECDHKey();
    clientPrivateKey = privateKey;
    clientPublicKey = publicKey;

    client.write(publicKey);
});

client.on('data', (data) => {
    if (!serverPublicKey) {
        // Step 2: Receive server's public key and compute shared secret
        serverPublicKey = data;
        sharedSecret = protocol.initiateKeyExchange(clientPrivateKey, serverPublicKey);

        rl.question('Enter a message for the server: ', (message) => {
            // Step 3: Encrypt the message and send it to the server
            const encryptedMessage = protocol.encrypt(sharedSecret, Buffer.from(message));
            client.write(encryptedMessage);
        });
    } else {
        // Step 4: Receive the encrypted response from the server and decrypt it
        const decryptedResponse = protocol.decrypt(sharedSecret, data);
        console.log('Server Response: ' + decryptedResponse.toString());
        client.end();
    }
});

client.on('end', () => {
    console.log('Disconnected from server');
});
