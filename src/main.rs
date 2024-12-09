mod server;
mod client;
mod client_auth;

use server::Server;
use client_auth::*;
use inquire::{Text, Select};
use anyhow::Result;



fn register(server: &mut Server) -> Result<()> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let client = client::Client::new(username, &password);
    server.register(client)?;
    Ok(())
}

fn authenticate(server: &mut Server) -> Result<()> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let salt = server.getSalt(username.as_str());
    let clientAuth = ClientAuth::new(&password, salt?);
    let client = client::Client::new(username, &password);
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
