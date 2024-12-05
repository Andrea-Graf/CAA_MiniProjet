use inquire::Password;
use rand_core::{OsRng, RngCore, CryptoRng};

use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};


pub struct Client {
    pub username: String,
    pub password_hash: String,
    pub public_key_encryption: String,
    pub private_key_encryption: String,
    pub public_key_signature: String,
    pub private_key_signature: String,
    pub salt: String,
}

impl Client {
    fn new(username : String, password: String) -> Self {
        let salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::default();
        let mut output_key_material = [0u8; 96]; // Can be any desired size
        argon2.hash_password_into(password.as_bytes(), &salt, &mut output_key_material).unwrap();

        let password_hash = output_key_material[..64].to_vec(); // 512 bits = 64 bytes
        let key = output_key_material[64..].to_vec(); // 256 bits = 32 bytes


        let public_key_encryption = todo!();
        let private_key_encryption = todo!();
        let public_key_signature = todo!();
        let private_key_signature = todo!();

        Client {
            username,
            password_hash,
            public_key_encryption,
            private_key_encryption,
            public_key_signature,
            private_key_signature,
            salt,
        }
    }
}