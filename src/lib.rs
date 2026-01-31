use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use wasm_bindgen::prelude::*;
use pqcrypto_dilithium::dilithium3;
#[cfg(target_arch = "wasm32")]
use getrandom as _; 

#[wasm_bindgen]
pub struct KeyPair {
    pub_key: Vec<u8>,
    sec_key: Vec<u8>,
}

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> { self.pub_key.clone() }
    
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> { self.sec_key.clone() }
}

#[wasm_bindgen]
pub fn generate_keypair() -> KeyPair {
    let (pk, sk) = dilithium3::keypair();
    KeyPair {
        pub_key: pk.as_bytes().to_vec(),
        sec_key: sk.as_bytes().to_vec(),
    }
}

#[wasm_bindgen]
pub fn sign_detached(msg: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let sk = dilithium3::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| JsValue::from_str("Invalid SecretKey length"))?;
    // 2. Ký thông điệp
    let sig = dilithium3::detached_sign(msg, &sk);
    // 3. Chuyển signature sang Vec<u8> thông qua trait Signature
    Ok(sig.as_bytes().to_vec())
}
