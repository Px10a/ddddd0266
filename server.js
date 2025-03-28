const net = require('net');
const { CustomProtocol, KeyHelper } = require('./index'); // Assuming the provided code is saved in cryptoProtocol.js

const server = net.createServer((socket) => {
    const protocol = new CustomProtocol();
    let serverPrivateKey, serverPublicKey, clientPublicKey, sharedSecret;

    socket.on('data', (data) => {
        if (!serverPrivateKey) {
            // Step 1: Key exchange (Server)
            serverPrivateKey = KeyHelper.generateECDHKey().privateKey;
            serverPublicKey = KeyHelper.generateECDHKey().publicKey;

            // Send server public key to client
            socket.write(serverPublicKey);
        } else {
            // Step 2: Client sends their public key, server computes shared secret
            clientPublicKey = data;
            sharedSecret = protocol.initiateKeyExchange(serverPrivateKey, clientPublicKey);

            // Step 3: Receive the message from the client
            const decryptedMessage = protocol.decrypt(sharedSecret, data);

            // Encrypt a response message and send back to the client
            const responseMessage = 'Server Response: ' + decryptedMessage.toString();
            const encryptedResponse = protocol.encrypt(sharedSecret, Buffer.from(responseMessage));

            socket.write(encryptedResponse);
        }
    });

    socket.on('end', () => {
        console.log('Connection ended');
    });
});

server.listen(8000, () => {
    console.log('Server started on port 8000');
});
