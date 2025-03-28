use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use rand::Rng;
use sha2::{Sha256, Digest};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::ec::{EcKey, EcGroup};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::derive::Deriver;

extern crate zlib;

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

fn aes_256_ctr_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    
    let cipher = Cipher::aes_256_ctr();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&iv)).unwrap();
    
    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let count = crypter.update(plaintext, &mut ciphertext).unwrap();
    crypter.finalize(&mut ciphertext[count..]).unwrap();
    
    [iv.to_vec(), ciphertext].concat()
}

fn aes_256_gcm_encrypt(key: &[u8], plaintext: &[u8], associated_data: Option<&[u8]>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut iv = [0u8; 12];
    rng.fill(&mut iv);
    
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&iv)).unwrap();
    
    if let Some(data) = associated_data {
        crypter.set_aad(data).unwrap();
    }
    
    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let count = crypter.update(plaintext, &mut ciphertext).unwrap();
    crypter.finalize(&mut ciphertext[count..]).unwrap();
    
    let tag = crypter.get_tag().unwrap();
    
    [iv.to_vec(), tag.to_vec(), ciphertext].concat()
}

fn aes_256_gcm_decrypt(key: &[u8], ciphertext: &[u8], associated_data: Option<&[u8]>) -> Vec<u8> {
    let (iv, tag, data) = ciphertext.split_at(12);
    let tag = &tag[..16];
    
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).unwrap();
    crypter.set_tag(tag).unwrap();
    
    if let Some(data) = associated_data {
        crypter.set_aad(data).unwrap();
    }
    
    let mut plaintext = vec![0; data.len()];
    let count = crypter.update(data, &mut plaintext).unwrap();
    crypter.finalize(&mut plaintext[count..]).unwrap();
    
    plaintext
}

fn compress_data(data: &[u8]) -> Vec<u8> {
    let mut encoder = zlib::Encoder::new(Vec::new()).unwrap();
    encoder.write_all(data).unwrap();
    encoder.finish().into_result().unwrap()
}

fn decompress_data(data: &[u8]) -> Vec<u8> {
    let mut decoder = zlib::Decoder::new(data).unwrap();
    let mut decoded_data = Vec::new();
    decoder.read_to_end(&mut decoded_data).unwrap();
    decoded_data
}

struct Cryptmanx {
    private_key: EcKey,
    public_key: EcKey,
}

impl Cryptmanx {
    fn new() -> Self {
        let (private_key, public_key) = generate_ecdh_key();
        Cryptmanx {
            private_key,
            public_key,
        }
    }

    fn key_exchange(&self, peer_public_key: &EcKey) -> Vec<u8> {
        ecdh_shared_secret(&self.private_key, peer_public_key)
    }

    fn encrypt_data(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let compressed_data = compress_data(data);
        aes_256_gcm_encrypt(key, &compressed_data, None)
    }

    fn decrypt_data(&self, key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let decrypted_data = aes_256_gcm_decrypt(key, ciphertext, None);
        decompress_data(&decrypted_data)
    }
}
