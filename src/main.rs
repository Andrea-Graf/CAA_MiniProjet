mod server;
mod client;
mod client_auth;
mod authenticate_data;
mod message_app;

use std::fmt::Formatter;
use std::{env, fs};
use server::Server;
use client_auth::*;
use inquire::{Text, Select};
use anyhow::Result;
use chrono::NaiveDateTime;
use dryoc::dryocbox::{DryocBox, StackByteArray};
use dryoc::sign::SigningKeyPair;
use inquire::formatter::DateFormatter;

fn register(server: &mut Server) -> Result<()> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let client = client::Client::new(username, &password);
    let result = server.register(client)?;
    Ok(())
}

fn authenticate(server: &mut Server) -> Result<ClientAuth> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let salt = server.getSalt(username.as_str());
    let mut clientAuth = ClientAuth::new(&password, salt.unwrap());
    let client = server.authenticate(username.as_str(), clientAuth.password_hash.clone()).unwrap();
    clientAuth.Complete(client);
    Ok(clientAuth)
}

fn reset_password(server: &mut Server) -> Result<()> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let salt = server.getSalt(username.as_str());
    let mut clientAuth = ClientAuth::new(&password, salt?);
    let client = client::Client::new(username, &password);
    clientAuth.Complete(&client);
    Ok(())
}

fn send_message(server: &mut Server) -> Result<()> {
    let client_auth = authenticate(server)?;
    let recipient = Text::new("Enter the recipient:").prompt()?;
    let file_path = Text::new("Enter the file path:").prompt()?;
    let date_input = Text::new("Enter the date (minute-hour-day-month-year):").prompt()?;


    NaiveDateTime::parse_from_str(&date_input, "%M-%H-%d-%m-%Y")
        .map_err(|_| anyhow::anyhow!("Invalid date format. Use minute-hour-day-month-year."))?;

    if fs::read(&file_path).is_err() {
        return Err(anyhow::anyhow!("Unable to read file"));
    }

    let file_name = file_path.split("/").last().unwrap();
    let file = fs::read(&file_path).unwrap();

    client_auth.send_message(recipient.as_str(),file_name, file, date_input.as_str(), server);
    Ok(())
}

fn receive_message(server: &mut Server) -> Result<()> {
    let clientAuth = authenticate(server)?;
    let boiteDeReception =  server.receive_message(&clientAuth);
    let keysign: dryoc::sign::SigningKeyPair<dryoc::sign::PublicKey, dryoc::dryocbox::StackByteArray<64>> = SigningKeyPair::from_secret_key(clientAuth.private_key_signature.clone());

    // Create the reception directory and user-specific subdirectory if they do not exist
    let mut user_reception_dir = format!("reception/{}", clientAuth.username);
    fs::create_dir_all(&user_reception_dir)?;

    for messageApp in boiteDeReception {
        println!("From: {}", messageApp.authenticate_data.sender);
        println!("Date: {}", messageApp.authenticate_data.date);

        let file_encrypted = DryocBox::from_bytes(&messageApp.file_encrypted).expect("failed to read box");
        let file_name_encrypted = DryocBox::from_bytes(&messageApp.file_name_encrypted).expect("failed to read box");

        let public_key_sender = server.get_public_key(&messageApp.authenticate_data.sender).expect("unable to get public key");

        let file_name_vec = file_name_encrypted.decrypt_to_vec(&messageApp.nonce_file_name, &public_key_sender, &clientAuth.private_key_encryption).expect("unable to decrypt");
        let file_name = String::from_utf8(file_name_vec).expect("unable to convert to string");
        user_reception_dir.push_str(format!("/{}", file_name).as_str());

        println!("{:?}", &messageApp.nonce_file);
        println!("{:?}", &StackByteArray::<24>::default());

        if !messageApp.nonce_file.eq(&StackByteArray::<24>::default())  {
            let file = file_encrypted.decrypt_to_vec(&messageApp.nonce_file, &public_key_sender, &clientAuth.private_key_encryption).expect("unable to decrypt");
            let file_content = String::from_utf8(file).expect("unable to convert to string");
            fs::write(&user_reception_dir , file_content).expect("Unable to write file");

        }else{
            fs::write(&user_reception_dir, messageApp.file_encrypted).expect("Unable to write file");
        }
        // Écrire le message dans un fichier
        println!("Message saved to {:?}", user_reception_dir);

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
