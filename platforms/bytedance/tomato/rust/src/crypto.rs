use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD, Engine};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

const REGISTER_KEY: [u8; 16] = [
    0xac, 0x25, 0xc6, 0x7d, 0xdd, 0x8f, 0x38, 0xc1,
    0xb3, 0x7a, 0x23, 0x48, 0x82, 0x8e, 0x22, 0x2e,
];

pub fn build_register_content_with_iv(device_id: i64, user_id: i64, iv: &[u8; 16]) -> String {
    let mut plain = Vec::with_capacity(16);
    plain.extend_from_slice(&device_id.to_le_bytes());
    plain.extend_from_slice(&user_id.to_le_bytes());
    let cipher = Aes128CbcEnc::new((&REGISTER_KEY).into(), iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(&plain);
    let mut encoded = Vec::with_capacity(16 + cipher.len());
    encoded.extend_from_slice(iv);
    encoded.extend_from_slice(&cipher);
    STANDARD.encode(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_content_vector() {
        let iv = *b"1234567890123456";
        assert_eq!(
            build_register_content_with_iv(643680972856619, 0, &iv),
            "MTIzNDU2Nzg5MDEyMzQ1NmT9l3XkgzNyg0UjVJC8plSSyMLM14MlZHMvtUg5WT/i"
        );
    }
}
