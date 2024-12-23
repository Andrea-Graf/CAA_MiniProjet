use std::collections::HashMap;
use anyhow::{anyhow, Error};
use anyhow::Result;
use chrono::{Duration, NaiveDateTime};
use dryoc::classic::crypto_box::{Nonce, PublicKey};
use dryoc::dryocbox::{ByteArray, DryocBox, Mac};
use dryoc::pwhash::Salt;
use dryoc::sign::{Message, SignedMessage, SigningKeyPair};
use dryoc::types::StackByteArray;
use inquire::formatter::DateFormatter;
use inquire::validator::CustomTypeValidator;
use crate::authenticate_data::AuthenticateData;
use crate::client::Client;
use crate::client_auth::ClientAuth;
use crate::message_app::MessageApp;

pub struct Server{
    users: HashMap<String, Client>,
}

impl Server {
    pub fn new() -> Self {
        Server {
            users: HashMap::new(),
        }
    }
    pub fn verify_auth(&self, username: &str, password_hash: &[u8]) -> std::result::Result<(), Error> {
        if let Some(client) = self.users.get(username) {
            if client.password_hash == password_hash {
                Ok(())
            } else {
                Err(anyhow!("Authentication failed: password hash mismatch"))
            }
        } else {
            Err(anyhow!("Authentication failed: user not found"))
        }
    }

    pub fn register(&mut self, client: Client) -> Result<()> {
        if self.users.contains_key(&client.username) {
            return Err(anyhow!("Username already exists"));
        }
        self.users.insert(client.username.clone(), client);
        Ok(())
    }
    pub fn getSalt(&self, username: &str) -> Result<Salt> {
        if let Some(client) = self.users.get(username) {
            Ok(client.salt.clone())
        } else {
            Err(anyhow!("User not found"))
        }
    }
    pub fn authenticate(&self, username: &str, password: Vec<u8>) -> Result<&Client, anyhow::Error> {
        
        if let Some(client) = self.users.get(username)  {
           if (client.password_hash == password) {
                Ok(client)
           } else {
               Err(anyhow!("Invalid password"))
           }

        } else {
            Err(anyhow!("User not found"))
        }
    }
    pub fn get_public_key_encrypt(&self, username: &str) -> Result<&dryoc::keypair::PublicKey, anyhow::Error> {
        if let Some(client) = self.users.get(username) {
            Ok(&client.public_key_encryption)
        } else {
            Err(anyhow!("User not found"))
        }
    }
    pub fn get_public_key_sign(&self, username: &str) -> Result<&dryoc::keypair::PublicKey, anyhow::Error> {
        if let Some(client) = self.users.get(username) {
            Ok(&client.public_key_signature)
        } else {
            Err(anyhow!("User not found"))
        }
    }
    pub fn send_message(&mut self, username: &str, password_hash: &[u8], authenticate_data_signed: AuthenticateData, nonce_file: StackByteArray<24>, nonce_file_name: StackByteArray<24>, file_encrypted: Vec<u8>, file_name_encrypted: Vec<u8>) -> Result<()> {
        self.verify_auth(username, password_hash)?;

        let message_app = MessageApp::new(authenticate_data_signed.clone(), nonce_file, nonce_file_name, file_encrypted, file_name_encrypted);
        self.users.get_mut(&authenticate_data_signed.receiver).unwrap().boiteDeReception.push(message_app);
        Ok(())
    }
    pub fn receive_message(&self, username: &str, password_hash: &[u8]) -> Result<Vec<MessageApp>> {
        self.verify_auth(username, password_hash)?;

        let boite_de_reception = &self.users.get(username).unwrap().boiteDeReception;
        let mut boite_de_reception_autorise = Vec::new();

        let current_date_time = chrono::Utc::now().naive_utc() + Duration::hours(1);

        for message_app in boite_de_reception {
            let date_time = NaiveDateTime::parse_from_str(&message_app.authenticate_data.date, "%M-%H-%d-%m-%Y");
            let mut message_autorise = message_app.clone();
            if date_time.unwrap() > current_date_time {
                message_autorise.nonce_file = StackByteArray::<24>::default();
            }
            boite_de_reception_autorise.push(message_autorise);
        }
        Ok(boite_de_reception_autorise)
    }
    pub fn reset_password(&mut self, username: &str, password_hash: &[u8], new_hash: Vec<u8>, new_salt: Salt, private_key_encryption: Vec<u8>, private_key_signature: Vec<u8>, nonce_encrypt: Nonce, nonce_signature: Nonce) -> Result<()> {
        self.verify_auth(username, password_hash)?;

        let user = self.users.get_mut(username).unwrap();
        user.password_hash = new_hash;
        user.salt = new_salt;
        user.private_key_encryption_ENCRYPT = private_key_encryption;
        user.private_key_signature_ENCRYPT = private_key_signature;
        user.nonceEncrypt = nonce_encrypt;
        user.nonceSignature = nonce_signature;

        Ok(())
    }


}