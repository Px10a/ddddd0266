use pyo3::prelude::*;
use openssl::aes::{AesKey, aes_ige};
use openssl::symm::Mode;
use openssl::ec::{EcKey, EcGroup};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use rand::Rng;
use sha2::{Sha256, Digest};
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

    fn encrypt_data(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        aes_256_ige_encrypt_py(key.to_vec(), data.to_vec(), iv.to_vec())
    }

    fn decrypt_data(&self, key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        aes_256_ige_decrypt_py(key.to_vec(), ciphertext.to_vec(), iv.to_vec())
    }

    // File encryption and compression
    fn encrypt_file(&self, key: &[u8], input_file: &str, output_file: &str) {
        let mut input = File::open(input_file).unwrap();
        let mut data = Vec::new();
        input.read_to_end(&mut data).unwrap();

        // Compress data before encryption
        let compressed_data = self.compress_data(&data);

        // Encrypt the compressed data
        let encrypted_data = self.encrypt_data(key, &compressed_data);

        // Write encrypted data to the output file
        let mut output = File::create(output_file).unwrap();
        output.write_all(&encrypted_data).unwrap();
    }

    // File decryption and decompression
    fn decrypt_file(&self, key: &[u8], input_file: &str, output_file: &str) {
        let mut input = File::open(input_file).unwrap();
        let mut encrypted_data = Vec::new();
        input.read_to_end(&mut encrypted_data).unwrap();

        // Decrypt the file content
        let decrypted_data = self.decrypt_data(key, &encrypted_data);

        // Decompress data after decryption
        let decompressed_data = self.decompress_data(&decrypted_data);

        // Write decompressed data to the output file
        let mut output = File::create(output_file).unwrap();
        output.write_all(&decompressed_data).unwrap();
    }

    // Compression (Gzip)
    fn compress_data(&self, data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    // Decompression (Gzip)
    fn decompress_data(&self, data: &[u8]) -> Vec<u8> {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed_data = Vec::new();
        decoder.read_to_end(&mut decompressed_data).unwrap();
        decompressed_data
    }
}

// Create the Python module
#[pymodule]
fn cryptmanx(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(aes_256_ige_encrypt_py, m)?)?;
    m.add_function(wrap_pyfunction!(aes_256_ige_decrypt_py, m)?)?;
    Ok(())
}
