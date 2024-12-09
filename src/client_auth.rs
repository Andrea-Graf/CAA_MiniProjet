use inquire::Password;

use dryoc::*;
use dryoc::auth::Mac;
use dryoc::classic::crypto_box::Nonce;
use dryoc::dryocbox::{KeyPair, NewByteArray, StackByteArray};
use dryoc::dryocsecretbox::DryocSecretBox;
use dryoc::kx::SecretKey;
use dryoc::pwhash::*;
use dryoc::sign::PublicKey;
use crate::client::Client;

pub struct ClientAuth {
    pub username: String,
    pub password_hash: Vec<u8>,
    pub key : Vec<u8>,
    pub private_key_encryption: SecretKey,
    pub private_key_signature: SecretKey,
    pub salt: Salt,
}

impl ClientAuth {
    pub fn new(password: &str, salt: Salt) -> Self {
        let output_argon2: VecPwHash = PwHash::hash_with_salt(
            &password.as_bytes().to_vec(),
            salt.clone(),
            Config::default(),
        ).expect("unable to hash password with salt");

        let pass_hash = output_argon2.into_parts();
        let password_hash = pass_hash.0[..64].to_vec(); // 512 bits = 64 bytes
        let key =pass_hash.0[64..].to_vec(); // 256 bits = 32 bytes

        ClientAuth{
            username: "".to_string(),
            password_hash,
            key,
            private_key_encryption: SecretKey::default(),
            private_key_signature: SecretKey::default(),
            salt,
        }

    }
    pub fn Complete(&mut self, client: Client) -> () {
        self.username = client.username.clone();

        let private_key_encryption_ENCRYPT = DryocSecretBox::from_bytes(&client.private_key_encryption_ENCRYPT).expect("unable to load box");
        let private_key_signature_ENCRYPT = DryocSecretBox::from_bytes(&client.private_key_signature_ENCRYPT).expect("unable to load box");


        let private_key_encryption = private_key_encryption_ENCRYPT.decrypt_to_vec(&client.nonceEncrypt, &self.key).expect("unable to decrypt");
        let private_key_signature = private_key_signature_ENCRYPT.decrypt_to_vec(&client.nonceSignature, &self.key).expect("unable to decrypt");

        self.private_key_encryption = SecretKey::from(&private_key_encryption);
        self.private_key_signature = SecretKey::from(&private_key_signature);
    }
}

