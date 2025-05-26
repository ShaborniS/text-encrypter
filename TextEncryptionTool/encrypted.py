from cryptography.fernet import Fernet
import os
import logging

logging.basicConfig(
    filename="activity.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class TextEncryptor:
    def __init__(self, key_file="secret.key"):
        self.key_file = key_file
        if not os.path.exists(self.key_file):
            self.write_key()
        self.key = self.load_key()
        self.cipher = Fernet(self.key)

    def write_key(self):
        key = Fernet.generate_key()
        with open(self.key_file, "wb") as key_file:
            key_file.write(key)
        logging.info("Generated and saved new encryption key.")

    def load_key(self):
        return open(self.key_file, "rb").read()

    def encrypt_text(self, text):
        encrypted = self.cipher.encrypt(text.encode())
        encrypted_str = encrypted.decode()
        logging.info("Encrypted text: " + encrypted_str)

        with open("encrypted.txt", "w") as file:
            file.write(encrypted_str)

        print("🔐 Encrypted text saved to encrypted.txt.")
        return encrypted_str

    def decrypt_text(self, encrypted_text):
        try:
            decrypted = self.cipher.decrypt(encrypted_text.encode()).decode()
            logging.info("Decrypted text: " + decrypted)
            return decrypted
        except Exception:
            logging.warning("Failed to decrypt. Possibly invalid text or key.")
            return None

def main():
    encryptor = TextEncryptor()

    while True:
        print("\n--- Text Encryption Tool (OOP Version) ---")
        print("1. Encrypt Text")
        print("2. Decrypt Text (from input)")
        print("3. Decrypt Text (from file)")
        print("4. Exit")

        choice = input("Choose an option (1/2/3/4): ").strip()

        if choice == "1":
            plain = input("Enter text to encrypt: ")
            encryptor.encrypt_text(plain)

        elif choice == "2":
            encrypted = input("Paste the encrypted text: ")
            decrypted = encryptor.decrypt_text(encrypted)
            if decrypted:
                print("🔓 Decrypted Text:", decrypted)
            else:
                print("❌ Decryption failed.")

        elif choice == "3":
            if os.path.exists("encrypted.txt"):
                with open("encrypted.txt", "r") as f:
                    encrypted = f.read()
                print(f"📁 Loaded text: {encrypted}")
                decrypted = encryptor.decrypt_text(encrypted)
                if decrypted:
                    print("🔓 Decrypted Text:", decrypted)
                else:
                    print("❌ Decryption failed.")
            else:
                print("❌ encrypted.txt not found.")

        elif choice == "4":
            print("Goodbye!")
            break

        else:
            print("❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    main()