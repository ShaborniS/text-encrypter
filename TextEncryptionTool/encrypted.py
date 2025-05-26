import os
import logging
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

logging.basicConfig(
    filename="activity.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class TextEncryptor:
    def __init__(self):
        # Fernet key
        self.fernet_key_file = "fernet.key"
        if not os.path.exists(self.fernet_key_file):
            self.write_fernet_key()
        self.fernet_key = self.load_key(self.fernet_key_file)
        self.fernet_cipher = Fernet(self.fernet_key)

        # AES key
        self.aes_key_file = "aes.key"
        if not os.path.exists(self.aes_key_file):
            self.write_aes_key()
        self.aes_key = self.load_key(self.aes_key_file)

        # DES key
        self.des_key_file = "des.key"
        if not os.path.exists(self.des_key_file):
            self.write_des_key()
        self.des_key = self.load_key(self.des_key_file)

        # RSA keys
        self.rsa_private_key_file = "rsa_private.pem"
        self.rsa_public_key_file = "rsa_public.pem"
        if not os.path.exists(self.rsa_private_key_file) or not os.path.exists(self.rsa_public_key_file):
            self.generate_rsa_keys()
        self.rsa_private_key = RSA.import_key(open(self.rsa_private_key_file, "rb").read())
        self.rsa_public_key = RSA.import_key(open(self.rsa_public_key_file, "rb").read())
        self.rsa_cipher_encrypt = PKCS1_OAEP.new(self.rsa_public_key)
        self.rsa_cipher_decrypt = PKCS1_OAEP.new(self.rsa_private_key)

    # --- Key management ---
    def write_fernet_key(self):
        key = Fernet.generate_key()
        with open(self.fernet_key_file, "wb") as f:
            f.write(key)
        logging.info("Generated and saved new Fernet key.")

    def write_aes_key(self):
        key = get_random_bytes(16)  # AES-128
        with open(self.aes_key_file, "wb") as f:
            f.write(key)
        logging.info("Generated and saved new AES key.")

    def write_des_key(self):
        key = get_random_bytes(8)  # DES key size 8 bytes
        with open(self.des_key_file, "wb") as f:
            f.write(key)
        logging.info("Generated and saved new DES key.")

    def generate_rsa_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        with open(self.rsa_private_key_file, "wb") as f:
            f.write(private_key)
        with open(self.rsa_public_key_file, "wb") as f:
            f.write(public_key)
        logging.info("Generated and saved new RSA key pair.")

    def load_key(self, filename):
        return open(filename, "rb").read()

    # --- Encryption and Decryption ---
    def encrypt_text(self, text, algorithm="fernet"):
        if algorithm == "fernet":
            encrypted = self.fernet_cipher.encrypt(text.encode())
            encrypted_str = encrypted.decode()
        elif algorithm == "aes":
            cipher = AES.new(self.aes_key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
            encrypted_str = (cipher.iv + ct_bytes).hex()
        elif algorithm == "des":
            cipher = DES.new(self.des_key, DES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(text.encode(), DES.block_size))
            encrypted_str = (cipher.iv + ct_bytes).hex()
        elif algorithm == "rsa":
            encrypted_bytes = self.rsa_cipher_encrypt.encrypt(text.encode())
            encrypted_str = encrypted_bytes.hex()
        else:
            raise ValueError("Unsupported algorithm")

        logging.info(f"Encrypted text with {algorithm}: {encrypted_str}")
        with open("encrypted.txt", "w") as file:
            file.write(encrypted_str)

        print(f"🔐 Encrypted text saved to encrypted.txt using {algorithm}.")
        return encrypted_str

    def decrypt_text(self, encrypted_text, algorithm="fernet"):
        try:
            if algorithm == "fernet":
                decrypted = self.fernet_cipher.decrypt(encrypted_text.encode()).decode()
            elif algorithm == "aes":
                data = bytes.fromhex(encrypted_text)
                iv = data[:16]
                ct = data[16:]
                cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode()
            elif algorithm == "des":
                data = bytes.fromhex(encrypted_text)
                iv = data[:8]
                ct = data[8:]
                cipher = DES.new(self.des_key, DES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(ct), DES.block_size).decode()
            elif algorithm == "rsa":
                encrypted_bytes = bytes.fromhex(encrypted_text)
                decrypted = self.rsa_cipher_decrypt.decrypt(encrypted_bytes).decode()
            else:
                raise ValueError("Unsupported algorithm")

            logging.info(f"Decrypted text with {algorithm}: {decrypted}")
            return decrypted
        except Exception as e:
            logging.warning(f"Failed to decrypt with {algorithm}. Exception: {str(e)}")
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

        if choice in {"1", "2"}:
            print("Available algorithms: fernet, aes, des, rsa")
            algorithm = input("Choose algorithm: ").strip().lower()
            if algorithm not in {"fernet", "aes", "des", "rsa"}:
                print("❌ Invalid algorithm choice.")
                continue

        if choice == "1":
            plain = input("Enter text to encrypt: ")
            encryptor.encrypt_text(plain, algorithm)

        elif choice == "2":
            encrypted = input("Paste the encrypted text: ")
            decrypted = encryptor.decrypt_text(encrypted, algorithm)
            if decrypted:
                print("🔓 Decrypted Text:", decrypted)
            else:
                print("❌ Decryption failed.")

        elif choice == "3":
            if os.path.exists("encrypted.txt"):
                with open("encrypted.txt", "r") as f:
                    encrypted = f.read()
                print(f"📁 Loaded text: {encrypted}")
                # For file decrypting, you can ask or assume an algorithm, here ask:
                algorithm = input("Choose algorithm for decryption (fernet, aes, des, rsa): ").strip().lower()
                if algorithm not in {"fernet", "aes", "des", "rsa"}:
                    print("❌ Invalid algorithm choice.")
                    continue
                decrypted = encryptor.decrypt_text(encrypted, algorithm)
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