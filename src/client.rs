use inquire::Password;

use dryoc::*;
use dryoc::auth::Mac;
use dryoc::classic::crypto_box::Nonce;
use dryoc::dryocbox::{KeyPair, NewByteArray};
use dryoc::dryocsecretbox::DryocSecretBox;
use dryoc::kx::SecretKey;
use dryoc::pwhash::*;
use dryoc::sign::{PublicKey, SigningKeyPair};
use dryoc::types::StackByteArray;
use crate::message_app::MessageApp;

pub struct Client {
    pub username: String,
    pub password_hash: Vec<u8>,
    pub private_key_encryption_ENCRYPT: Vec<u8>,
    pub public_key_encryption: PublicKey,
    pub private_key_signature_ENCRYPT: Vec<u8>,
    pub public_key_signature: StackByteArray<32>,
    pub salt: Salt,
    pub nonceEncrypt: Nonce,
    pub nonceSignature: Nonce,
    pub boiteDeReception: Vec<MessageApp>,
}

impl Client {
    pub fn new(username : String, password: &str) -> Self {
        let mut salt = Salt::default();
        salt.resize(dryoc::constants::CRYPTO_PWHASH_SALTBYTES, 0);
        dryoc::rng::copy_randombytes(&mut salt);

        let config = Config::default();
        let custom_config = config.with_hash_length(96);

        let output_argon2: VecPwHash = PwHash::hash_with_salt(
            &password.as_bytes().to_vec(),
            salt.clone(),
            custom_config,
        ).expect("unable to hash password with salt");

        let pass_hash = output_argon2.into_parts();
        let password_hash = pass_hash.0[..64].to_vec(); // 512 bits = 64 bytes
        let key =pass_hash.0[64..].to_vec(); // 256 bits = 32 bytes

        let key_encryption = KeyPair::gen();
        let key_signature = SigningKeyPair::gen_with_defaults();

        let nonce_encrypt = Nonce::gen();
        let nonce_signature = Nonce::gen();

        let pkEn = DryocSecretBox::encrypt_to_vecbox(&key_encryption.secret_key.to_vec(), &nonce_encrypt, &key);
        let pkSi = DryocSecretBox::encrypt_to_vecbox(&key_signature.secret_key.to_vec(), &nonce_signature, &key);

        let private_key_encryption_ENCRYPT = pkEn.to_vec();
        let private_key_signature_ENCRYPT = pkSi.to_vec();


        Client {
            username,
            password_hash,
            private_key_encryption_ENCRYPT,
            public_key_encryption: key_encryption.public_key.clone(),
            private_key_signature_ENCRYPT,
            public_key_signature: key_signature.public_key.clone(),
            salt,
            nonceEncrypt: nonce_encrypt.clone(),
            nonceSignature: nonce_signature.clone(),
            boiteDeReception: Vec::new(),
        }
    }
}