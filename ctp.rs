use pyo3::prelude::*;
use openssl::aes::{AesKey, aes_ige};
use openssl::symm::Mode;
use openssl::ec::{EcKey, EcGroup};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use flate2::{Compression, write::GzEncoder, read::GzDecoder};

#[pyfunction]
fn aes_256_ige_encrypt_py(key: Vec<u8>, plaintext: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    let aes_key = AesKey::new_encrypt(&key).unwrap();
    let mut iv_copy = iv.clone();
    let mut ciphertext = vec![0; plaintext.len()];
    aes_ige(&plaintext, &mut ciphertext, &aes_key, &mut iv_copy, Mode::Encrypt);
    ciphertext
}

#[pyfunction]
fn aes_256_ige_decrypt_py(key: Vec<u8>, ciphertext: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    let aes_key = AesKey::new_decrypt(&key).unwrap();
    let mut iv_copy = iv.clone();
    let mut plaintext = vec![0; ciphertext.len()];
    aes_ige(&ciphertext, &mut plaintext, &aes_key, &mut iv_copy, Mode::Decrypt);
    plaintext
}

fn generate_ecdh_key() -> (EcKey, EcKey) {
    let group = EcGroup::from_curve_name(openssl::nid::Nid::X9_62_P256).unwrap();
    let private_key = EcKey::generate(&group).unwrap();
    let public_key = EcKey::from_public_key(&group, &private_key.public_key()).unwrap();
    (private_key, public_key)
}

fn ecdh_shared_secret(private_key: &EcKey, peer_public_key: &EcKey) -> Vec<u8> {
    let shared_secret = private_key.compute_shared_secret(peer_public_key).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.finalize().to_vec()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

struct SealedSender {
    private_key: EcKey,
    public_key: EcKey,
}

impl SealedSender {
    fn new() -> Self {
        let (private_key, public_key) = generate_ecdh_key();
        SealedSender { private_key, public_key }
    }

    fn key_exchange(&self, peer_public_key: &EcKey) -> Vec<u8> {
        ecdh_shared_secret(&self.private_key, peer_public_key)
    }

    fn encrypt_data(&self, key: &[u8], data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        let ciphertext = aes_256_ige_encrypt_py(key.to_vec(), data.to_vec(), iv.to_vec());

        // Generate HMAC for integrity check
        let hmac = hmac_sha256(key, &ciphertext);

        (ciphertext, hmac)
    }

    fn decrypt_data(&self, key: &[u8], ciphertext: &[u8], hmac: &[u8], iv: &[u8]) -> Vec<u8> {
        // Verify HMAC for integrity
        let computed_hmac = hmac_sha256(key, &ciphertext);
        if computed_hmac != hmac {
            panic!("HMAC mismatch! Data integrity compromised.");
        }

        // Decrypt the data
        aes_256_ige_decrypt_py(key.to_vec(), ciphertext.to_vec(), iv.to_vec())
    }

    // Encrypt and write metadata alongside data
    fn encrypt_file_with_metadata(&self, key: &[u8], input_file: &str, output_file: &str, metadata: &[u8]) {
        let mut input = File::open(input_file).unwrap();
        let mut data = Vec::new();
        input.read_to_end(&mut data).unwrap();

        // Encrypt metadata
        let metadata_encrypted = aes_256_ige_encrypt_py(key.to_vec(), metadata.to_vec(), vec![0; 16]);

        // Encrypt the data
        let (encrypted_data, hmac) = self.encrypt_data(key, &data);

        // Write the encrypted metadata and data to the output file
        let mut output = File::create(output_file).unwrap();
        output.write_all(&metadata_encrypted).unwrap();  // Write encrypted metadata first
        output.write_all(&hmac).unwrap();                // Write HMAC of the data
        output.write_all(&encrypted_data).unwrap();     // Write encrypted data
    }

    // Decrypt file and extract metadata
    fn decrypt_file_with_metadata(&self, key: &[u8], input_file: &str, output_file: &str) {
        let mut input = File::open(input_file).unwrap();
        let mut encrypted_metadata = vec![0; 16];  // Assuming metadata is 16 bytes
        let mut hmac = vec![0; 32];                // HMAC-SHA256 is 32 bytes
        let mut encrypted_data = Vec::new();

        input.read_exact(&mut encrypted_metadata).unwrap();
        input.read_exact(&mut hmac).unwrap();
        input.read_to_end(&mut encrypted_data).unwrap();

        // Decrypt metadata
        let metadata = aes_256_ige_decrypt_py(key.to_vec(), encrypted_metadata, vec![0; 16]);

        // Decrypt data and verify integrity using HMAC
        let decrypted_data = self.decrypt_data(key, &encrypted_data, &hmac, &vec![0; 16]);

        // Write decrypted data to the output file
        let mut output = File::create(output_file).unwrap();
        output.write_all(&decrypted_data).unwrap();

        // Optionally, return the metadata
        println!("Decrypted metadata: {:?}", metadata);
    }
}

// Create the Python module
#[pymodule]
fn cryptmanx(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(aes_256_ige_encrypt_py, m)?)?;
    m.add_function(wrap_pyfunction!(aes_256_ige_decrypt_py, m)?)?;
    Ok(())
}
