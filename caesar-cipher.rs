use std::fs::File;
use std::env;
use std::io::{self, Write, Read};

fn main() {
    println!("This program is designed for encrypting and decrypting texts using the Caesar cipher.");
    println!("Select the mode: press E to encipher and press D to decipher.");
    let text = file_opener().expect("FAILED TO OPEN THE FILE!");

    let mode: char = choose_mode();
    match mode {
	'E' | 'e' => encrypt(&text),
	'D' | 'd' => decrypt(&text),
            _     => println!("Invalid mode selected. Please, restart the program."),
    }
    
}

fn choose_mode() -> char {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("FAILED TO READ THE CHOICE.");
    input.trim().chars().next().unwrap_or(' ')
}

fn file_opener() -> Result<File, std::io::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
	return Err(io::Error::new(io::ErrorKind::InvalidInput, "You have to provide just one file"));
    }
    
    let file = File::open(&args[1])?;
    Ok(file)
}

fn encrypt(plain_text: &File) {
    println!("Encryption mode selected.");
    println!("The implemented Caesar cipher works in accordance with the formula C = P + K (mod 26),");
    println!("where C is the ciphered text, P is the plain text, and K is your key.");
    println!("Now, enter your integer key (positive key means the letter shifting to the right and negative key means shifting to the left).");
    println!("The key is: ");
    let mut input_key = String::new();
    io::stdin()
	.read_line(&mut input_key)
	.expect("FAILED TO READ THE KEY!");
    let mut key: i32 = input_key
	.trim()
	.parse()
	.expect("FAILED TO PARSE THE INPUT KEY!");
    key = key % 26;
    if key > 0 {
	key = key + 26;
    } else {
	key = 26 - key;
    }
    
    let mut encrypted_text = String::new();
    let mut reader = io::BufReader::new(plain_text);
    let mut plain_text_as_string = String::new();
    let _ = reader.read_to_string(&mut plain_text_as_string);

    for word in plain_text_as_string.split_whitespace() {
	for letter in word.chars() {
	    let mut encrypted_ascii_letter = letter as u8;

	    if letter.is_ascii_lowercase() {
		encrypted_ascii_letter = (encrypted_ascii_letter - b'a' + key as u8) % 26 + b'a';
	    } else if letter.is_ascii_uppercase() {
		encrypted_ascii_letter = (encrypted_ascii_letter - b'A' + key as u8) % 26 + b'A';
	    }

	  
	    let encrypted_letter = encrypted_ascii_letter as char;
	    encrypted_text.push(encrypted_letter);
	}

	encrypted_text.push(' ');
    }
    
    encrypted_text = encrypted_text.trim_end().to_string();
    let mut encrypted_file = File::create("encrypted.txt").expect("FAILED TO CREATE A FILE.");
    encrypted_file.write_all(encrypted_text.as_bytes()).expect("FAILED TO INSERT THE ENCRYPTED TEXT TO FILE.");

    println!("Encryption complete. Encrypted text saved to 'encrypted.txt'.");
}

fn decrypt(enciphered_text: &File) {
    println!("Decryption mode selected.");
    println!("The code will output all possible variants of the decrypted text into the file.");
    println!("The program does not use machine learning techniques to automatically determine which of the outputs is correct,");
    println!("but it will be obvious to the human reader from the look into the file. All variants have the used key printed before them.");

    let mut decrypted_text = String::new();
    let mut reader = io::BufReader::new(enciphered_text);
    let mut enciphered_text_as_string = String::new();
    let _ = reader.read_to_string(&mut enciphered_text_as_string);

    for key in 1..27 {
	decrypted_text.push_str("****************************************************\n");
	decrypted_text.push_str(&format!("KEY = {}:\n", key));
	for word in enciphered_text_as_string.split_whitespace() {
	    for letter in word.chars() {
		let mut decrypted_ascii_letter = letter as u8;

		if letter.is_ascii_lowercase() {
		    decrypted_ascii_letter = (decrypted_ascii_letter - b'a' + key as u8) % 26 + b'a';
		} else if letter.is_ascii_uppercase() {
		    decrypted_ascii_letter = (decrypted_ascii_letter - b'A' + key as u8) % 26 + b'A';
		}

		
		let decrypted_letter = decrypted_ascii_letter as char;
		decrypted_text.push(decrypted_letter);
	    }

	    decrypted_text.push(' ');
	}
	decrypted_text.push('\n');
    }
    decrypted_text = decrypted_text.trim_end().to_string();
    let mut decrypted_file = File::create("decrypted.txt").expect("FAILED TO CREATE A FILE.");
    decrypted_file.write_all(decrypted_text.as_bytes()).expect("FAILED TO INSERT THE ENCRYPTED TEXT TO FILE.");

    
    println!("Decryption complete. All variants of decrypted text saved to 'decrypted.txt'.");
}
