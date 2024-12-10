use dryoc::sign::{Message, SignedMessage, SigningKeyPair};

pub(crate) struct AuthenticateData {
    pub(crate) sender: String,
    pub(crate) receiver: String,
    pub(crate) date: String,
    pub(crate) signature:  SignedMessage<dryoc::types::StackByteArray<64>, Vec<u8>>,
}

impl AuthenticateData {
    pub(crate) fn clone(&self) -> AuthenticateData {
        AuthenticateData {
            sender: self.sender.clone(),
            receiver: self.receiver.clone(),
            date: self.date.clone(),
            signature: self.signature.clone(),
        }
    }
}

impl AuthenticateData{
    pub fn new(sender: String, receiver: String, date: String, signing_key: &SigningKeyPair<dryoc::sign::PublicKey, dryoc::dryocbox::StackByteArray<64>>) -> Self {
        let mut message = Message::new();
        message.extend_from_slice(sender.as_bytes());
        message.extend_from_slice(receiver.as_bytes());
        message.extend_from_slice(date.as_bytes());


        AuthenticateData {
            sender,
            receiver,
            date,
            signature: signing_key.sign_with_defaults(message).expect("unable to sign"),
        }
    }

    pub fn verify_detached(&self, public_key: &SigningKeyPair<dryoc::sign::PublicKey, dryoc::dryocbox::StackByteArray<64>>) -> bool {

        self.signature.verify(&public_key.public_key).is_ok()
    }

}
