use std::env;
mod aes;
mod helpers;

use aes::{decrypt_file, encrypt_file};
use helpers::get_password;

fn main() {
    // Get command line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 || args.len() > 4 {
        println!("Usage: ./gep --<mode> <path>");
        println!("Modes: enc, dec");
        println!("Optional: --del to delete original file after encryption/decryption");
        return;
    }

    // Parse command line arguments
    let mut mode = "";
    let mut file = "";
    let mut delete = false;

    for arg in args.iter() {
        if arg.starts_with("--") {
            if arg == "--enc" || arg == "--dec" {
                mode = arg;
            } else if arg == "--del" {
                delete = true;
            } else {
                println!("Unknown argument: {}", arg);
                return;
            }
        } else {
            file = arg;
        }
    }

    // Sanitize file path
    let file = file.replace(['\"', '\''], "");

    // Check if file exists and isn't a directory
    let path = std::path::Path::new(&file);

    if !path.exists() {
        println!("File not found");
        return;
    } else if path.is_dir() {
        println!("Path is a directory, not a file");
        return;
    }

    let password_str = get_password("Enter password: ");

    match mode as &str {
        "--enc" => {
            let confirm_password = get_password("Confirm password: ");

            if password_str != confirm_password {
                println!("Passwords do not match !");
                return;
            }
            match encrypt_file(&file, &password_str, delete) {
                Ok(_) => (),
                Err(e) => eprintln!("Error: {:?}", e),
            }
        }
        "--dec" => match decrypt_file(&file, &password_str, delete) {
            Ok(_) => (),
            Err(e) => eprintln!("Error: {:?}", e),
        },
        _ => {
            println!("Invalid mode");
        }
    }
}
