use std::collections::HashMap;
use anyhow::anyhow;
use anyhow::Result;
use chrono::NaiveDateTime;
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
    pub fn send_message(&mut self, authenticate_data_signed: AuthenticateData, nonce: StackByteArray<24>, message_encrypted: Vec<u8>) {
        let messageApp = MessageApp::new(authenticate_data_signed.clone(), nonce, message_encrypted);
        &self.users.get_mut(&authenticate_data_signed.sender).unwrap().boiteDeReception.push(messageApp);

    }
    pub fn receive_message(&self, client: &ClientAuth) -> Vec<MessageApp> {

        let mut boiteDeReception = &self.users.get(&client.username).unwrap().boiteDeReception;
        let mut boiteDeReceptionAutorise = Vec::new();

        let current_date_time = chrono::Utc::now().naive_utc();

        for  messageApp in boiteDeReception {
            let date_time = NaiveDateTime::parse_from_str(&messageApp.authenticate_data.date, "%M-%H-%d-%m-%Y");
            let mut messageAutorise  = messageApp.clone();
            if date_time.unwrap() < current_date_time {
                messageAutorise.nonce = StackByteArray::<24>::default();
            }
            boiteDeReceptionAutorise.push(messageAutorise);
        }
        boiteDeReceptionAutorise
    }


}