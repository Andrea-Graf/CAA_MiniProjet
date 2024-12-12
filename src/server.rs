use std::collections::HashMap;
use anyhow::anyhow;
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
    pub fn verify_auth(&self, client_auth: &ClientAuth) -> Result<()> {
        if let Some(client) = self.users.get(&client_auth.username) {
            if client.password_hash == client_auth.password_hash {
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
    pub fn get_public_key(&self, username: &str) -> Result<&dryoc::keypair::PublicKey, anyhow::Error> {
        if let Some(client) = self.users.get(username) {
            Ok(&client.public_key_encryption)
        } else {
            Err(anyhow!("User not found"))
        }
    }
    pub fn send_message(&mut self, client_auth: &ClientAuth , authenticate_data_signed: AuthenticateData, nonce_file: StackByteArray<24>,nonce_file_name: StackByteArray<24>, file_encrypted: Vec<u8>, file_name_encrypted: Vec<u8>) -> () {
        &self.verify_auth(client_auth);

        let messageApp = MessageApp::new(authenticate_data_signed.clone(), nonce_file, nonce_file_name, file_encrypted, file_name_encrypted);
        &self.users.get_mut(&authenticate_data_signed.receiver).unwrap().boiteDeReception.push(messageApp);
    }
    pub fn receive_message(&self, client_auth: &ClientAuth) -> Vec<MessageApp> {

        &self.verify_auth(client_auth);

        let mut boiteDeReception = &self.users.get(&client_auth.username).unwrap().boiteDeReception;
        let mut boiteDeReceptionAutorise = Vec::new();

        let current_date_time = chrono::Utc::now().naive_utc() + Duration::hours(1);

        for  messageApp in boiteDeReception {
            let date_time = NaiveDateTime::parse_from_str(&messageApp.authenticate_data.date, "%M-%H-%d-%m-%Y");
            let mut messageAutorise  = messageApp.clone();
            if date_time.unwrap() > current_date_time {
                messageAutorise.nonce_file = StackByteArray::<24>::default();
            }
            boiteDeReceptionAutorise.push(messageAutorise);
        }
        boiteDeReceptionAutorise
    }
    pub fn reset_password(&mut self, client_auth: &ClientAuth, new_hash: Vec<u8>, new_sel: Salt,private_key_encryption : Vec<u8>, private_key_signature : Vec<u8> , nonce_encrypt: Nonce, nonce_signature:Nonce) -> Result<()> {
        &self.verify_auth(&client_auth)?;

        self.users.get_mut(&client_auth.username).unwrap().password_hash = new_hash;
        self.users.get_mut(&client_auth.username).unwrap().salt = new_sel;
        self.users.get_mut(&client_auth.username).unwrap().private_key_encryption_ENCRYPT = private_key_encryption;
        self.users.get_mut(&client_auth.username).unwrap().private_key_signature_ENCRYPT = private_key_signature;
        self.users.get_mut(&client_auth.username).unwrap().nonceEncrypt = nonce_encrypt;
        self.users.get_mut(&client_auth.username).unwrap().nonceSignature = nonce_signature;



        Ok(())
    }


}