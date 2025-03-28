const net = require('net');
const { CustomProtocol, KeyHelper } = require('./index');

const server = net.createServer((socket) => {
    console.log('Client connected.');

    const protocol = new CustomProtocol();
    const serverIdentityKeyPair = protocol.generateIdentityKeyPair();
    
    // Send the public key to the client
    socket.write(serverIdentityKeyPair.publicKey);

    // Receive client's public key
    socket.once('data', (clientPublicKey) => {
        console.log('Received client public key.');
        
        // Compute shared secret
        const sharedSecret = protocol.initiateKeyExchange(serverIdentityKeyPair.privateKey, clientPublicKey);
        const encryptionKey = KeyHelper.hkdf(sharedSecret);

        console.log('Shared secret established.');

        // Encrypt and send message
        const message = Buffer.from('Hello from server');
        const encryptedMessage = protocol.encrypt(encryptionKey, message);
        socket.write(encryptedMessage);
        
        console.log('Encrypted message sent.');
    });

    socket.on('close', () => console.log('Client disconnected.'));
});

server.listen(3000, () => console.log('Server listening on port 3000'));
