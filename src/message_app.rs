use crate::authenticate_data::AuthenticateData;

pub(crate) struct MessageApp {
    pub(crate) authenticate_data: AuthenticateData,
    pub(crate) nonce: dryoc::types::StackByteArray<24>,
    pub(crate) message_encrypted: Vec<u8>,
}

impl MessageApp {
    pub fn new(authenticate_data: AuthenticateData, nonce: dryoc::types::StackByteArray<24>, message_encrypted: Vec<u8>) -> Self {
        MessageApp {
            authenticate_data,
            nonce,
            message_encrypted,
        }
    }
    pub(crate) fn clone(&self) -> MessageApp {
        MessageApp {
            authenticate_data: self.authenticate_data.clone(),
            nonce: self.nonce.clone(),
            message_encrypted: self.message_encrypted.clone(),
        }
    }

}