import sodium from 'libsodium-wrappers';

/**
 * Interface for a Double Ratchet message
 */
export interface DoubleRatchetMessage {
  header: {
    ratchetKey: Uint8Array;      // The public key used in this ratchet step
    messageIndex: number;       // Counter for messages in this chain
    previousChainLength: number; // Number of messages in the previous chain
    nonce: Uint8Array;          // Nonce used for encryption
  };
  ciphertext: Uint8Array; // The encrypted message
}

/**
 * Class representing the Double Ratchet protocol
 */
export class DoubleRatchet {
  private rootKey: Uint8Array;
  private sendingChainKey: Uint8Array | null = null;
  private receivingChainKey: Uint8Array | null = null;
  private messageIndex: number = 0;
  private previousChainLength: number = 0;
  private ratchetKeyPair: sodium.KeyPair;
  private remoteRatchetKey: Uint8Array | null = null;

  /**
   * Constructor for the Double Ratchet protocol
   * @param initialRootKey Initial root key used to derive chain keys
   * @param initialRatchetKeyPair Initial key pair for the ratchet
   */
  constructor(initialRootKey: Uint8Array, initialRatchetKeyPair: sodium.KeyPair) {
    this.rootKey = initialRootKey;
    this.ratchetKeyPair = initialRatchetKeyPair;
  }

  /**
   * Initializes the Double Ratchet instance
   * @param initialRootKey Initial root key to start the chain
   * @returns An instance of the Double Ratchet class
   */
  public static async create(initialRootKey: Uint8Array): Promise<DoubleRatchet> {
    await sodium.ready;
    const ratchetKeyPair = sodium.crypto_kx_keypair(); // Generate initial ratchet key pair
    return new DoubleRatchet(initialRootKey, ratchetKeyPair);
  }

  /**
   * Perform a Diffie-Hellman key exchange and derive a shared secret
   * @param privateKey The sender's private key
   * @param publicKey The receiver's public key
   * @returns Shared secret derived from the Diffie-Hellman exchange
   */
  private async deriveSharedSecret(
    privateKey: Uint8Array,
    publicKey: Uint8Array
  ): Promise<Uint8Array> {
    return sodium.crypto_scalarmult(privateKey, publicKey);
  }

  /**
   * Advance the root key and derive new chain keys for sending and receiving
   * @param sharedSecret Shared secret derived from Diffie-Hellman
   */
  private async advanceRootKey(sharedSecret: Uint8Array): Promise<void> {
    this.rootKey = sodium.crypto_generichash(32, sharedSecret, this.rootKey);
    this.sendingChainKey = sodium.crypto_generichash(32, new Uint8Array([0x01]), this.rootKey);
    this.receivingChainKey = sodium.crypto_generichash(32, new Uint8Array([0x02]), this.rootKey);
  }

  /**
   * Generate a new nonce for encryption
   * @returns A random nonce
   */
  private generateNonce(): Uint8Array {
    return sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  }

  /**
   * Encrypt a message using the sending chain key
   * @param plaintext The plaintext message to be encrypted
   * @returns Encrypted message wrapped in a Double Ratchet message format
   */
  public async encryptMessage(plaintext: string): Promise<DoubleRatchetMessage> {
    if (!this.sendingChainKey) {
      throw new Error('Sending chain key has not been initialized.');
    }

    const derivedKey = sodium.crypto_generichash(32, this.sendingChainKey);
    const nonce = this.generateNonce();
    const ciphertext = sodium.crypto_secretbox_easy(
      sodium.from_string(plaintext),
      nonce,
      derivedKey
    );

    // Advance sending chain key
    this.sendingChainKey = sodium.crypto_generichash(32, this.sendingChainKey);

    const header = {
      ratchetKey: this.ratchetKeyPair.publicKey,
      messageIndex: this.messageIndex,
      previousChainLength: this.previousChainLength,
      nonce: nonce, // Include nonce in the header
    };

    this.messageIndex++;

    return { header, ciphertext };
  }

  /**
   * Decrypt a received message using the receiving chain key
   * @param message The encrypted message to be decrypted
   * @returns Decrypted plaintext message
   */
  public async decryptMessage(message: DoubleRatchetMessage): Promise<string> {
    if (!this.receivingChainKey) {
      throw new Error('Receiving chain key has not been initialized.');
    }

    const derivedKey = sodium.crypto_generichash(32, this.receivingChainKey);
    const plaintext = sodium.crypto_secretbox_open_easy(
      message.ciphertext,
      message.header.nonce,
      derivedKey
    );

    if (!plaintext) {
      throw new Error('Decryption failed.');
    }

    // Advance receiving chain key
    this.receivingChainKey = sodium.crypto_generichash(32, this.receivingChainKey);

    return sodium.to_string(plaintext);
  }

  /**
   * Perform a ratchet step to establish new keys after receiving a message
   * @param remotePublicKey The public key of the remote peer
   */
  public async performRatchetStep(remotePublicKey: Uint8Array): Promise<void> {
    const sharedSecret = await this.deriveSharedSecret(
      this.ratchetKeyPair.privateKey,
      remotePublicKey
    );
    await this.advanceRootKey(sharedSecret);

    // Generate a new ratchet key pair for the next steps
    this.ratchetKeyPair = sodium.crypto_kx_keypair();
    this.remoteRatchetKey = remotePublicKey;

    // Reset message counters
    this.previousChainLength = this.messageIndex;
    this.messageIndex = 0;
  }
}
