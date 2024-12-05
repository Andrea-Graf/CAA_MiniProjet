use std::collections::HashMap;
use std::hash::Hash;
use anyhow::anyhow;
use anyhow::Result;
use inquire::Password;
use inquire::validator::CustomTypeValidator;
use crate::client::Client;

struct Server{
    users: HashMap<String, Client>,
}

impl Server {
    fn new() -> Self {
        Server {
            users: HashMap::new(),
        }
    }

    fn register(&mut self, client: Client) -> Result<()> {
        if self.users.contains_key(&client.username) {
            return Err(anyhow!("Username already exists"));
        }
        self.users.insert(client.username.clone(), client);
        Ok(())
    }

    fn authenticate(&self, username: &str, password: &str) -> Result<Client, Err()> {
        if let Some(client) = self.users.get(username)  {
           if (client.password_hash.validate(password)) {
                Ok(client)
           } else {
               Err(anyhow!("Invalid password"));
           }

        } else {
            Err(anyhow!("User not found"))
        }
    }
}