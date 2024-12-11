use crate::authenticate_data::AuthenticateData;

pub(crate) struct MessageApp {
    pub(crate) authenticate_data: AuthenticateData,
    pub(crate) nonce_file: dryoc::types::StackByteArray<24>,
    pub(crate) nonce_file_name: dryoc::types::StackByteArray<24>,
    pub(crate) file_encrypted: Vec<u8>,
    pub(crate) file_name_encrypted: Vec<u8>,
}

impl MessageApp {
    pub fn new(authenticate_data: AuthenticateData, nonce_file: dryoc::types::StackByteArray<24>,nonce_file_name: dryoc::types::StackByteArray<24>, file_encrypted: Vec<u8>, file_name_encrypted: Vec<u8>) -> Self {
        MessageApp {
            authenticate_data,
            nonce_file,
            nonce_file_name,
            file_encrypted,
            file_name_encrypted,
        }
    }
    pub(crate) fn clone(&self) -> MessageApp {
        MessageApp {
            authenticate_data: self.authenticate_data.clone(),
            nonce_file: self.nonce_file.clone(),
            nonce_file_name: self.nonce_file_name.clone(),
            file_encrypted: self.file_encrypted.clone(),
            file_name_encrypted: self.file_name_encrypted.clone(),
        }
    }

}