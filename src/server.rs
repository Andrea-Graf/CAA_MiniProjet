use std::collections::HashMap;
use anyhow::anyhow;
use anyhow::Result;
use dryoc::pwhash::Salt;
use inquire::validator::CustomTypeValidator;
use crate::client::Client;

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

    pub fn send_message(){
        // TODO
    }
    pub fn receive_message(){
        // TODO
    }


}