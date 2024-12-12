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

    let mut salt = Salt::default();
    salt.resize(dryoc::constants::CRYPTO_PWHASH_SALTBYTES, 0);
    dryoc::rng::copy_randombytes(&mut salt);

    let config = Config::default();
    let custom_config = config.with_hash_length(96);

    let output_argon2: VecPwHash = PwHash::hash_with_salt(
        &new_password.as_bytes().to_vec(),
        salt.clone(),
        custom_config,
    ).expect("unable to hash password with salt");

    let pass_hash = output_argon2.into_parts();
    let password_hash = pass_hash.0[..64].to_vec(); // 512 bits = 64 bytes
    let key =pass_hash.0[64..].to_vec(); // 256 bits = 32 bytes

    let nonce_encrypt = Nonce::gen();
    let nonce_signature = Nonce::gen();

    let private_key_encryption =  DryocSecretBox::encrypt_to_vecbox(&client_auth.private_key_encryption,&nonce_encrypt , &key).to_vec();
    let private_key_signature = DryocSecretBox::encrypt_to_vecbox(&client_auth.private_key_signature,&nonce_signature , &key).to_vec();

    server.reset_password(client_auth, password_hash, salt, private_key_encryption, private_key_signature, nonce_encrypt, nonce_signature)?;
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

    let boite_de_reception = server.receive_message(client_auth);
    let keysign: dryoc::sign::SigningKeyPair<dryoc::sign::PublicKey, dryoc::dryocbox::StackByteArray<64>> = SigningKeyPair::from_secret_key(client_auth.private_key_signature.clone());


    let mut user_reception_dir = format!("reception/{}", &client_auth.username);
    fs::create_dir_all(&user_reception_dir)?;

    for message_app in boite_de_reception {
        println!("From: {}", message_app.authenticate_data.sender);
        println!("Date: {}", message_app.authenticate_data.date);

        let file_encrypted = DryocBox::from_bytes(&message_app.file_encrypted).expect("failed to read box");
        let file_name_encrypted = DryocBox::from_bytes(&message_app.file_name_encrypted).expect("failed to read box");

        let public_key_sender = server.get_public_key(&message_app.authenticate_data.sender)?;

        let file_name_vec = file_name_encrypted.decrypt_to_vec(&message_app.nonce_file_name, &public_key_sender, &client_auth.private_key_encryption)?;
        let file_name = String::from_utf8(file_name_vec)?;
        user_reception_dir.push_str(format!("/{}", file_name).as_str());

        if !message_app.nonce_file.eq(&StackByteArray::<24>::default())   {
            let file = file_encrypted.decrypt_to_vec(&message_app.nonce_file, &public_key_sender, &client_auth.private_key_encryption)?;
            fs::write(&user_reception_dir, file)?;
        } else {
            fs::write(&user_reception_dir, &message_app.file_encrypted)?;
        }

        println!("Message saved to {:?}", user_reception_dir);

        if message_app.authenticate_data.verify_detached(&keysign) {
            println!("Signature valid");
        } else {
            println!("Signature invalid");
        }
    }
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
