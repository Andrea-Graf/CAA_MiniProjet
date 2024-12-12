use std::fs;
use anyhow::Error;
use inquire::Password;

use dryoc::dryocbox::*;
use dryoc::dryocsecretbox::DryocSecretBox;
use dryoc::kx::SecretKey;
use dryoc::pwhash::*;
use crate::client::Client;
use crate::authenticate_data::AuthenticateData;
use dryoc::kx::*;
use dryoc::sign::*;
use inquire::formatter::DateFormatter;
use crate::server::Server;

pub struct ClientAuth {
    pub username: String,
    pub password_hash: Vec<u8>,
    pub key : Vec<u8>,
    pub private_key_encryption: SecretKey,
    pub private_key_signature: StackByteArray<64>,
    pub salt: Salt,
}

impl ClientAuth {
    pub fn new(password: &str, salt: Salt) -> Self {
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

        ClientAuth{
            username: "".to_string(),
            password_hash,
            key,
            private_key_encryption: SecretKey::default(),
            private_key_signature: StackByteArray::<64>::default(),
            salt,
        }

    }
    pub fn Complete(&mut self, client: &Client) -> () {
        self.username = client.username.clone();

        let private_key_encryption_ENCRYPT = DryocSecretBox::from_bytes(&client.private_key_encryption_ENCRYPT).expect("unable to load box");
        let private_key_signature_ENCRYPT = DryocSecretBox::from_bytes(&client.private_key_signature_ENCRYPT).expect("unable to load box");


        let private_key_encryption = private_key_encryption_ENCRYPT.decrypt_to_vec(&client.nonceEncrypt, &self.key).expect("unable to decrypt");
        let private_key_signature = private_key_signature_ENCRYPT.decrypt_to_vec(&client.nonceSignature, &self.key).expect("unable to decrypt");


        // Convertir Vec<u8> en SecretKey
        self.private_key_encryption = SecretKey::try_from(&private_key_encryption[..]).expect("unable to convert to SecretKey");
        self.private_key_signature = StackByteArray::<64>::try_from(&private_key_signature[..]).expect("unable to convert to SecretKey");
    }

    pub fn send_message(&self, recipient: &str,file_name: &str , file: Vec<u8>, date: &str, server: &mut Server) -> () {
        let recipient_public_key = server.get_public_key(recipient).expect("unable to get public key");
        let nonce_file = Nonce::gen();
        let nonce_file_name = Nonce::gen();

        let file_encrypted =  DryocBox::encrypt_to_vecbox(
            file.as_slice(),
            &nonce_file,
            &recipient_public_key,
            &self.private_key_encryption,
        ).expect("unable to encrypt");

        let file_name_encrypted = DryocBox::encrypt_to_vecbox(
            file_name.as_bytes(),
            &nonce_file_name,
            &recipient_public_key,
            &self.private_key_encryption,
        ).expect("unable to encrypt");

        let file_encrypted_box = file_encrypted.to_vec();
        let file_name_encrypted_box = file_name_encrypted.to_vec();

        let key: dryoc::sign::SigningKeyPair<dryoc::sign::PublicKey, dryoc::dryocbox::StackByteArray<64>> = SigningKeyPair::from_secret_key(self.private_key_signature.clone());
        let authenticate_data = AuthenticateData::new(self.username.clone(), recipient.to_string(), date.to_string(), &key);


        server.send_message(&self, authenticate_data, nonce_file, nonce_file_name, file_encrypted_box, file_name_encrypted_box);
    }
    // Méthode pour réinitialiser le mot de passe
    pub fn reset_password(&self, new_password: &str, server: &mut Server) -> Result<(), Error> {
        let mut salt = Salt::default();
        salt.resize(dryoc::constants::CRYPTO_PWHASH_SALTBYTES, 0);
        dryoc::rng::copy_randombytes(&mut salt);

        let config = Config::default();
        let custom_config = config.with_hash_length(96);

        let output_argon2: VecPwHash = PwHash::hash_with_salt(
            &new_password.as_bytes().to_vec(),
            salt.clone(),
            custom_config,
        ).expect("unable to hash password with salt");

        let pass_hash = output_argon2.into_parts();
        let password_hash = pass_hash.0[..64].to_vec(); // 512 bits = 64 bytes
        let key = pass_hash.0[64..].to_vec(); // 256 bits = 32 bytes

        let nonce_encrypt = dryoc::classic::crypto_box::Nonce::gen();
        let nonce_signature = dryoc::classic::crypto_box::Nonce::gen();;

        let private_key_encryption = DryocSecretBox::encrypt_to_vecbox(&self.private_key_encryption, &nonce_encrypt, &key).to_vec();
        let private_key_signature = DryocSecretBox::encrypt_to_vecbox(&self.private_key_signature, &nonce_signature, &key).to_vec();

        server.reset_password(self, password_hash, salt, private_key_encryption, private_key_signature, nonce_encrypt, nonce_signature)?;
        Ok(())
    }

    // Méthode pour recevoir des messages
    pub fn receive_message(&self, server: &Server) -> Result<(),Error> {
        let boite_de_reception = server.receive_message(self);
        let keysign: dryoc::sign::SigningKeyPair<dryoc::sign::PublicKey, dryoc::dryocbox::StackByteArray<64>> = SigningKeyPair::from_secret_key(self.private_key_signature.clone());

        let mut user_reception_dir = format!("reception/{}", &self.username);
        fs::create_dir_all(&user_reception_dir)?;

        for message_app in boite_de_reception {
            println!("From: {}", message_app.authenticate_data.sender);
            println!("Date: {}", message_app.authenticate_data.date);

            let file_encrypted = DryocBox::from_bytes(&message_app.file_encrypted).expect("failed to read box");
            let file_name_encrypted = DryocBox::from_bytes(&message_app.file_name_encrypted).expect("failed to read box");

            let public_key_sender = server.get_public_key(&message_app.authenticate_data.sender)?;

            let file_name_vec = file_name_encrypted.decrypt_to_vec(&message_app.nonce_file_name, &public_key_sender, &self.private_key_encryption)?;
            let file_name = String::from_utf8(file_name_vec)?;
            user_reception_dir.push_str(format!("/{}", file_name).as_str());

            if !message_app.nonce_file.eq(&StackByteArray::<24>::default()) {
                let file = file_encrypted.decrypt_to_vec(&message_app.nonce_file, &public_key_sender, &self.private_key_encryption)?;
                fs::write(&user_reception_dir, file)?;
            } else {
                fs::write(&user_reception_dir, &message_app.file_encrypted)?;
            }

            println!("Message saved to {:?}", user_reception_dir);

            if message_app.authenticate_data.verify_detached(&keysign) {
                println!("Signature valid");
            } else {
                println!("Signature invalid");
            }
        }
        Ok(())
    }
}

