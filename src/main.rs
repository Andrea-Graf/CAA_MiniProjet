mod server;
mod client;
mod client_auth;

use std::fmt::Formatter;
use server::Server;
use client_auth::*;
use inquire::{Text, Select};
use anyhow::Result;
use inquire::formatter::DateFormatter;

fn register(server: &mut Server) -> Result<()> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let client = client::Client::new(username, &password);
    server.register(client)?;
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

fn send_message(server: &mut Server, client_auth: ClientAuth) -> Result<()> {
    let recipient = Text::new("Enter the recipient:").prompt()?;
    let message = Text::new("Enter the message:").prompt()?;
    let date = Text::new("Enter the date (minute-hour-day-month-year):").prompt()?;

    client_auth.send_message(recipient.as_str(), message.as_str(), date, server);
    Ok(())
}

fn receive_message(server: &mut Server) -> Result<()> {
    let clientAuth = authenticate(server)?;
    server.receive_message(clientAuth)?;
    Ok(())
}

fn main() -> Result<()>{
    let mut server = Server::new();

    loop {
        let select = Select::new("What do you want to do?",
                                 vec!["register", "authenticate", "exit"])
            .prompt()?;

        let result = match select {
            "register" => register(&mut server),
            "authenticate" => register(&mut server),
            "exit" => return Ok(()),
            _ => unreachable!(),
        };

        if let Err(e) = result {
            eprintln!("{e}");
        }


    }
}
