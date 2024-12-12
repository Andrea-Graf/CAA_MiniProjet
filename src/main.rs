mod server;
mod client;
mod client_auth;
mod authenticate_data;
mod message_app;

use std::{env, fs};
use server::Server;
use client_auth::*;
use inquire::{Text, Select};
use anyhow::Result;
use chrono::NaiveDateTime;
use dryoc::classic::crypto_box::Nonce;
use dryoc::dryocbox::{DryocBox, StackByteArray};
use dryoc::dryocsecretbox::{DryocSecretBox, NewByteArray};
use dryoc::pwhash::{Config, PwHash, Salt, VecPwHash};
use dryoc::sign::SigningKeyPair;

struct AuthContext {
    client_auth: Option<ClientAuth>,
}

impl AuthContext {
    fn new() -> Self {
        AuthContext { client_auth: None }
    }

    fn is_authenticated(&self) -> bool {
        self.client_auth.is_some()
    }

    fn set_auth(&mut self, auth: ClientAuth) {
        self.client_auth = Some(auth);
    }

    fn clear_auth(&mut self) {
        self.client_auth = None;
    }

    fn get_auth(&self) -> Result<&ClientAuth> {
        self.client_auth
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("You must authenticate first."))
    }

    fn username(&self) -> Option<String> {
        self.client_auth.as_ref().map(|auth| auth.username.clone())
    }
}

fn register(server: &mut Server) -> Result<()> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let client = client::Client::new(username, &password);
    server.register(client)?;
    Ok(())
}

fn authenticate(server: &mut Server, auth_context: &mut AuthContext) -> Result<()> {
    auth_context.clear_auth();
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let salt = server.getSalt(username.as_str())?;

    let mut client_auth = ClientAuth::new(&password, salt);
    let client = server.authenticate(username.as_str(), client_auth.password_hash.clone())?;
    client_auth.Complete(client);

    auth_context.set_auth(client_auth);
    println!("Successfully authenticated as {}", username);
    Ok(())
}

fn reset_password(server: &mut Server, auth_context: &mut AuthContext) -> Result<()> {
    let client_auth = auth_context.get_auth()?;
    let new_password = Text::new("Enter your new password:").prompt()?;
    client_auth.reset_password(&new_password, server)?;
    authenticate(server, auth_context)?;
    Ok(())
}

fn send_message(server: &mut Server, auth_context: &AuthContext) -> Result<()> {
    let client_auth = auth_context.get_auth()?;

    let recipient = Text::new("Enter the recipient:").prompt()?;
    let file_path = Text::new("Enter the file path:").prompt()?;
    let date_input = Text::new("Enter the date (minute-hour-day-month-year):").prompt()?;

    NaiveDateTime::parse_from_str(&date_input, "%M-%H-%d-%m-%Y")
        .map_err(|_| anyhow::anyhow!("Invalid date format. Use minute-hour-day-month-year."))?;

    let file = fs::read(&file_path).map_err(|_| anyhow::anyhow!("Unable to read file"))?;
    let file_name = file_path.split('/').last().unwrap();

    client_auth.send_message(recipient.as_str(), file_name, file, date_input.as_str(), server);

    Ok(())
}

fn receive_message(server: &mut Server, auth_context: &AuthContext) -> Result<()> {
    let client_auth = auth_context.get_auth()?;
    client_auth.receive_message(server)?;
    Ok(())
}

fn main() -> Result<()> {
    let mut server = Server::new();
    let mut auth_context = AuthContext::new();

    loop {
        let username_display = auth_context
            .username()
            .map(|u| format!(" (Connected as: {})", u))
            .unwrap_or_default();

        let select = Select::new(
            &format!("What do you want to do?{}", username_display),
            vec![
                "register",
                "authenticate",
                "reset_password",
                "send_message",
                "receive_message",
                "logout",
                "exit",
            ],
        )
            .prompt()?;

        let result = match select {
            "register" => register(&mut server),
            "authenticate" => authenticate(&mut server, &mut auth_context),
            "reset_password" => reset_password(&mut server, &mut auth_context),
            "send_message" => send_message(&mut server, &auth_context),
            "receive_message" => receive_message(&mut server, &auth_context),
            "logout" => {
                auth_context.clear_auth();
                println!("You have been logged out.");
                Ok(())
            }
            "exit" => return Ok(()),
            _ => unreachable!(),
        };

        if let Err(e) = result {
            eprintln!("{e}");
        }
    }
}
