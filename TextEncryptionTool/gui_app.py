import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os
import logging
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
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

    def encrypt(self, text, algorithm="fernet"):
        if algorithm == "fernet":
            encrypted = self.fernet_cipher.encrypt(text.encode()).decode()
        elif algorithm == "aes":
            cipher = AES.new(self.aes_key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
            encrypted = (cipher.iv + ct_bytes).hex()
        elif algorithm == "des":
            cipher = DES.new(self.des_key, DES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(text.encode(), DES.block_size))
            encrypted = (cipher.iv + ct_bytes).hex()
        elif algorithm == "rsa":
            encrypted_bytes = self.rsa_cipher_encrypt.encrypt(text.encode())
            encrypted = encrypted_bytes.hex()
        else:
            raise ValueError("Unsupported algorithm")

        with open("encrypted.txt", "w") as f:
            f.write(encrypted)
        logging.info(f"Encrypted text with {algorithm}: {encrypted}")
        return encrypted

    def decrypt(self, text, algorithm="fernet"):
        try:
            if algorithm == "fernet":
                decrypted = self.fernet_cipher.decrypt(text.encode()).decode()
            elif algorithm == "aes":
                data = bytes.fromhex(text)
                iv = data[:16]
                ct = data[16:]
                cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode()
            elif algorithm == "des":
                data = bytes.fromhex(text)
                iv = data[:8]
                ct = data[8:]
                cipher = DES.new(self.des_key, DES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(ct), DES.block_size).decode()
            elif algorithm == "rsa":
                encrypted_bytes = bytes.fromhex(text)
                decrypted = self.rsa_cipher_decrypt.decrypt(encrypted_bytes).decode()
            else:
                raise ValueError("Unsupported algorithm")

            logging.info(f"Decrypted text with {algorithm}: {decrypted}")
            return decrypted
        except Exception as e:
            logging.warning(f"Failed to decrypt with {algorithm}. Exception: {e}")
            return "❌ Decryption Failed."

class TextEncrypterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Text Encryption Tool")
        self.root.geometry("650x450")
        self.root.resizable(False, False)

        self.encryptor = TextEncryptor()

        self._create_widgets()
        self._layout_widgets()

    def _create_widgets(self):
        # Labels
        self.input_label = tk.Label(self.root, text="Enter Text:")
        self.result_label = tk.Label(self.root, text="Output:")

        # Text areas
        self.input_text = scrolledtext.ScrolledText(self.root, height=6)
        self.result_text = scrolledtext.ScrolledText(self.root, height=6, state='disabled')

        # Algorithm selection
        self.alg_label = tk.Label(self.root, text="Choose Algorithm:")
        self.algorithm = ttk.Combobox(self.root, values=["fernet", "aes", "des", "rsa"], state="readonly")
        self.algorithm.current(0)

        # Buttons frame
        self.button_frame = tk.Frame(self.root)

        # Buttons
        self.encrypt_button = tk.Button(self.button_frame, text="Encrypt", command=self.encrypt_action)
        self.decrypt_button = tk.Button(self.button_frame, text="Decrypt", command=self.decrypt_action)
        self.load_button = tk.Button(self.button_frame, text="Load from File", command=self.load_from_file)
        self.view_log_button = tk.Button(self.button_frame, text="View Log", command=self.view_log)
        self.clear_log_button = tk.Button(self.button_frame, text="Clear Log", command=self.clear_log)
        self.clear_encrypted_button = tk.Button(self.button_frame, text="Clear Encrypted", command=self.clear_encrypted_file)

    def _layout_widgets(self):
        self.input_label.pack(pady=(10, 0))
        self.input_text.pack(fill='x', padx=10)

        self.alg_label.pack(pady=(10, 0))
        self.algorithm.pack(padx=10)

        self.result_label.pack(pady=(10, 0))
        self.result_text.pack(fill='x', padx=10)

        self.button_frame.pack(pady=15)

        self.encrypt_button.grid(row=0, column=0, padx=10)
        self.decrypt_button.grid(row=0, column=1, padx=10)
        self.load_button.grid(row=0, column=2, padx=10)
        self.view_log_button.grid(row=0, column=3, padx=10)
        self.clear_log_button.grid(row=1, column=0, padx=10, pady=5)
        self.clear_encrypted_button.grid(row=1, column=1, padx=10, pady=5)

    def encrypt_action(self):
        plain = self.input_text.get("1.0", tk.END).strip()
        algorithm = self.algorithm.get()
        if not plain:
            messagebox.showwarning("Input Error", "Enter text to encrypt.")
            return
        try:
            encrypted = self.encryptor.encrypt(plain, algorithm)
            self._update_result_text(encrypted)
            messagebox.showinfo("Success", f"Encrypted and saved to encrypted.txt using {algorithm}.")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_action(self):
        encrypted = self.input_text.get("1.0", tk.END).strip()
        algorithm = self.algorithm.get()
        if not encrypted:
            messagebox.showwarning("Input Error", "Enter encrypted text to decrypt.")
            return
        try:
            decrypted = self.encryptor.decrypt(encrypted, algorithm)
            self._update_result_text(decrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def load_from_file(self):
        if not os.path.exists("encrypted.txt"):
            messagebox.showerror("Error", "encrypted.txt not found.")
            return
        try:
            with open("encrypted.txt", "r") as file:
                content = file.read()
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert(tk.END, content)
            messagebox.showinfo("Loaded", "Encrypted text loaded into input box.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {e}")

    def view_log(self):
        if not os.path.exists("activity.log"):
            messagebox.showinfo("Info", "No logs available.")
            return
        try:
            with open("activity.log", "r") as log_file:
                content = log_file.read()
            log_window = tk.Toplevel(self.root)
            log_window.title("Activity Log")
            text_area = scrolledtext.ScrolledText(log_window, width=80, height=30)
            text_area.pack(fill='both', expand=True)
            text_area.insert(tk.END, content)
            text_area.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open log: {e}")

    def clear_log(self):
        if messagebox.askyesno("Confirm", "Clear the activity log?"):
            with open("activity.log", "w") as log_file:
                log_file.write("")
            messagebox.showinfo("Cleared", "Activity log cleared.")

    def clear_encrypted_file(self):
        if messagebox.askyesno("Confirm", "Clear the encrypted.txt file?"):
            with open("encrypted.txt", "w") as f:
                f.write("")
            messagebox.showinfo("Cleared", "encrypted.txt cleared.")

    def _update_result_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, text)
        self.result_text.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = TextEncrypterApp(root)
    root.mainloop()