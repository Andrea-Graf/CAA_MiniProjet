use inquire::Password;

use dryoc::dryocbox::*;
use dryoc::dryocsecretbox::DryocSecretBox;
use dryoc::kx::SecretKey;
use dryoc::pwhash::*;
use crate::client::Client;

use dryoc::kx::*;
use dryoc::sign::*;
use inquire::formatter::DateFormatter;
use crate::server::Server;

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

        // Convertir Vec<u8> en SecretKey
        self.private_key_encryption = SecretKey::try_from(&private_key_encryption[..]).expect("unable to convert to SecretKey");
        self.private_key_signature = SecretKey::try_from(&private_key_signature[..]).expect("unable to convert to SecretKey");
    }

    pub fn send_message(&self, recipient: &str, message: &str,date: &str, server: &Server) -> () {
        let recipient_public_key = server.get_public_key(recipient).expect("unable to get public key");
        let nonce = Nonce::default();

        let message_encrypted =  DryocBox::encrypt_to_vecbox(
            message,
            &nonce,
            recipient_public_key,
            &self.private_key_encryption,
        ).expect("unable to encrypt");

        let mut authenticate_data: Vec<u8> = Vec::new();
        authenticate_data.extend_from_slice(self.username.as_bytes());
        authenticate_data.extend_from_slice(recipient.as_bytes());
        authenticate_data.extend_from_slice(date.as_bytes());

        let signing_key = SigningKeyPair::from_secret_key(&self.private_key_signature).expect("unable to create signing key");
        let authenticate_data_signed = signing_key.sign(&authenticate_data);

        server.send_message(&authenticate_data_signed, &nonce, &message_encrypted);
    }
}

