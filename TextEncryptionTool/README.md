# Text Encrypter

A Python project for encrypting and decrypting text using symmetric encryption with the Fernet module from the cryptography library. It supports both command-line and graphical user interfaces (GUI).

## Features

- Encrypt plain text and save the encrypted output to a file (`encrypted.txt`)
- Decrypt encrypted text either from input or directly from the file
- Automatically generates and manages an encryption key (`secret.key`)
- Logs encryption and decryption activity to `activity.log`
- User-friendly GUI built with Tkinter for easier operation

## Installation

1. Clone or download the project
2. Install required Python packages using:

## Usage

### Command Line

1. Run the main script to encrypt or decrypt text via terminal prompts:


### GUI

2. Run the GUI app for an interactive window-based experience:

## Files Description

- `encrypted.py` — Main logic for terminal-based encryption/decryption  
- `gui_app.py` — GUI application to perform encryption and decryption  
- `secret.key` — Automatically generated encryption key file  
- `encrypted.txt` — File storing encrypted text  
- `activity.log` — Logs all encryption/decryption operations  
- `requirements.txt` — List of required Python packages

## Requirements

- Python 3.6 or newer  
- cryptography library  
- tkinter (usually included in Python standard library)

## License

This project is licensed under the MIT License.

---

For any issues or feature requests, please open an issue on the project repository.