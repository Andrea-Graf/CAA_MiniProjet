mod server;
mod client;
mod client_auth;
mod authenticate_data;
mod message_app;

use std::fmt::Formatter;
use server::Server;
use client_auth::*;
use inquire::{Text, Select};
use anyhow::Result;
use chrono::NaiveDateTime;
use dryoc::dryocbox::DryocBox;
use dryoc::sign::SigningKeyPair;
use inquire::formatter::DateFormatter;

fn register(server: &mut Server) -> Result<()> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let client = client::Client::new(username, &password);
    let result = server.register(client)?;
    if let Err(e) = result {
        eprintln!("{e}");
    }
    Ok(())
}

fn authenticate(server: &mut Server) -> Result<ClientAuth> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let salt = server.getSalt(username.as_str());
    let mut clientAuth = ClientAuth::new(&password, salt?);
    let client = client::Client::new(username, &password);
    clientAuth.Complete(client);
    Ok(clientAuth)
}

fn reset_password(server: &mut Server) -> Result<()> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let salt = server.getSalt(username.as_str());
    let mut clientAuth = ClientAuth::new(&password, salt?);
    let client = client::Client::new(username, &password);
    clientAuth.Complete(client);
    Ok(())
}

fn send_message(server: &mut Server) -> Result<()> {
    let client_auth = authenticate(server)?;
    let recipient = Text::new("Enter the recipient:").prompt()?;
    let message = Text::new("Enter the message:").prompt()?;
    let date_input = Text::new("Enter the date (minute-hour-day-month-year):").prompt()?;

    NaiveDateTime::parse_from_str(&date_input, "%M-%H-%d-%m-%Y")
        .map_err(|_| anyhow::anyhow!("Invalid date format. Use minute-hour-day-month-year."))?;

    client_auth.send_message(recipient.as_str(), message.as_str(), date_input.as_str(), server);
    Ok(())
}

fn receive_message(server: &mut Server) -> Result<()> {
    let clientAuth = authenticate(server)?;
    let boiteDeReception =  server.receive_message(&clientAuth);
    let keysign: dryoc::sign::SigningKeyPair<dryoc::sign::PublicKey, dryoc::dryocbox::StackByteArray<64>> = SigningKeyPair::from_secret_key(clientAuth.private_key_signature.clone());

    for messageApp in boiteDeReception {
        let message_encrypted = DryocBox::from_bytes(&messageApp.message_encrypted).expect("failed to read box");
        let public_key_sender = server.get_public_key(&messageApp.authenticate_data.sender).expect("unable to get public key");
        let message = message_encrypted.decrypt_to_vec(&messageApp.nonce, &public_key_sender, &clientAuth.private_key_encryption).expect("unable to decrypt");

        println!("From: {}", messageApp.authenticate_data.sender);
        println!("Date: {}", messageApp.authenticate_data.date);
        println!("Message: {}", String::from_utf8(message).expect("Invalid UTF-8 sequence"));
        if messageApp.authenticate_data.verify_detached(&keysign) {
            println!("Signature valid");
        } else {
            println!("Signature invalid");
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut server = Server::new();

    loop {
        let select = Select::new("What do you want to do?",
                                 vec!["register", "authenticate", "reset_password", "send_message", "receive_message", "exit"])
            .prompt()?;

        let result = match select {
            "register" => register(&mut server),
            "authenticate" => {
                authenticate(&mut server)?;
                Ok(())
            },
            "reset_password" => reset_password(&mut server),
            "send_message" => send_message(&mut server),
            "receive_message" => receive_message(&mut server),
            "exit" => return Ok(()),
            _ => unreachable!(),
        };

        if let Err(e) = result {
            eprintln!("{e}");
        }
    }
}
