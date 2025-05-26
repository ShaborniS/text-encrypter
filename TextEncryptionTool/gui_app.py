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

    # --- Helper methods ---
    def load_key(self, filename):
        with open(filename, "rb") as f:
            return f.read()

    def write_fernet_key(self):
        key = Fernet.generate_key()
        with open(self.fernet_key_file, "wb") as f:
            f.write(key)
        logging.info("Generated and saved new Fernet key.")

    def write_aes_key(self):
        key = get_random_bytes(16)  # AES-128 key size
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

    # --- Encryption & Decryption ---
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
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        self.encryptor = TextEncryptor()

        self._create_widgets()
        self._layout_widgets()
        self._apply_styles()
        self._bind_events()

    def _create_widgets(self):
        # Labels
        self.input_label = tk.Label(self.root, text="Enter Text:", font=("Helvetica", 12, "bold"))
        self.result_label = tk.Label(self.root, text="Output:", font=("Helvetica", 12, "bold"))

        # Text areas
        self.input_text = scrolledtext.ScrolledText(self.root, height=7, font=("Helvetica", 11), wrap=tk.WORD)
        self.result_text = scrolledtext.ScrolledText(self.root, height=7, font=("Helvetica", 11), wrap=tk.WORD, state='disabled')

        # Algorithm selection
        self.alg_label = tk.Label(self.root, text="Choose Algorithm:", font=("Helvetica", 12))
        self.algorithm = ttk.Combobox(self.root, values=["fernet", "aes", "des", "rsa"], state="readonly", font=("Helvetica", 11))
        self.algorithm.current(0)

        # Buttons frame
        self.button_frame = tk.Frame(self.root, bg="#f0f0f0")

        # Buttons with pastel background colors
        pastel_colors = ["#a8dadc", "#ffd6a5", "#ffafcc", "#cdb4db", "#b5ead7", "#f9c2ff"]
        self.encrypt_button = tk.Button(self.button_frame, text="Encrypt", bg=pastel_colors[0], fg="#222222", relief="flat", padx=15, pady=7, font=("Helvetica", 11, "bold"), cursor="hand2", activebackground="#8bc9cc")
        self.decrypt_button = tk.Button(self.button_frame, text="Decrypt", bg=pastel_colors[1], fg="#222222", relief="flat", padx=15, pady=7, font=("Helvetica", 11, "bold"), cursor="hand2", activebackground="#ffbf70")
        self.load_button = tk.Button(self.button_frame, text="Load from File", bg=pastel_colors[2], fg="#222222", relief="flat", padx=15, pady=7, font=("Helvetica", 11, "bold"), cursor="hand2", activebackground="#e292af")
        self.view_log_button = tk.Button(self.button_frame, text="View Log", bg=pastel_colors[3], fg="#222222", relief="flat", padx=15, pady=7, font=("Helvetica", 11, "bold"), cursor="hand2", activebackground="#b6a4d9")
        self.clear_log_button = tk.Button(self.button_frame, text="Clear Log", bg=pastel_colors[4], fg="#222222", relief="flat", padx=15, pady=7, font=("Helvetica", 11, "bold"), cursor="hand2", activebackground="#a0d6c6")
        self.clear_encrypted_button = tk.Button(self.button_frame, text="Clear Encrypted", bg=pastel_colors[5], fg="#222222", relief="flat", padx=15, pady=7, font=("Helvetica", 11, "bold"), cursor="hand2", activebackground="#d69aff")

    def _layout_widgets(self):
        padding_x = 15
        self.input_label.pack(pady=(15, 5), anchor='w', padx=padding_x)
        self.input_text.pack(fill='x', padx=padding_x)

        self.alg_label.pack(pady=(15, 5), anchor='w', padx=padding_x)
        self.algorithm.pack(padx=padding_x, fill='x')

        self.result_label.pack(pady=(15, 5), anchor='w', padx=padding_x)
        self.result_text.pack(fill='x', padx=padding_x)

        self.button_frame.pack(pady=20, padx=padding_x, fill='x')
        self.encrypt_button.grid(row=0, column=0, padx=4, pady=5)
        self.decrypt_button.grid(row=0, column=1, padx=4, pady=5)
        self.load_button.grid(row=0, column=2, padx=4, pady=5)
        self.view_log_button.grid(row=0, column=3, padx=4, pady=5)
        self.clear_log_button.grid(row=0, column=4, padx=4, pady=5)
        self.clear_encrypted_button.grid(row=0, column=5, padx=4, pady=5)

    def _apply_styles(self):
        # Font and colors already set inline, add hover effects:
        buttons = [self.encrypt_button, self.decrypt_button, self.load_button,
                   self.view_log_button, self.clear_log_button, self.clear_encrypted_button]

        def on_enter(e):
            e.widget['bg'] = "#ffd166"  # bright pastel yellow

        def on_leave(e):
            # revert to original pastel background
            mapping = {
                self.encrypt_button: "#a8dadc",
                self.decrypt_button: "#ffd6a5",
                self.load_button: "#ffafcc",
                self.view_log_button: "#cdb4db",
                self.clear_log_button: "#b5ead7",
                self.clear_encrypted_button: "#f9c2ff"
            }
            e.widget['bg'] = mapping[e.widget]

        for btn in buttons:
            btn.bind("<Enter>", on_enter)
            btn.bind("<Leave>", on_leave)

    def _bind_events(self):
        self.encrypt_button.config(command=self.encrypt_text)
        self.decrypt_button.config(command=self.decrypt_text)
        self.load_button.config(command=self.load_from_file)
        self.view_log_button.config(command=self.view_log)
        self.clear_log_button.config(command=self.clear_log)
        self.clear_encrypted_button.config(command=self.clear_encrypted_file)

    # Button command implementations
    def encrypt_text(self):
        text = self.input_text.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Warning", "Input text is empty.")
            return
        algo = self.algorithm.get()
        try:
            encrypted = self.encryptor.encrypt(text, algorithm=algo)
            self.result_text.config(state='normal')
            self.result_text.delete("1.0", "end")
            self.result_text.insert("1.0", encrypted)
            self.result_text.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_text(self):
        text = self.input_text.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Warning", "Input text is empty.")
            return
        algo = self.algorithm.get()
        try:
            decrypted = self.encryptor.decrypt(text, algorithm=algo)
            self.result_text.config(state='normal')
            self.result_text.delete("1.0", "end")
            self.result_text.insert("1.0", decrypted)
            self.result_text.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def load_from_file(self):
        if not os.path.exists("encrypted.txt"):
            messagebox.showinfo("Info", "No encrypted.txt file found.")
            return
        with open("encrypted.txt", "r") as f:
            content = f.read()
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", content)

    def view_log(self):
        if not os.path.exists("activity.log"):
            messagebox.showinfo("Info", "No activity.log file found.")
            return
        with open("activity.log", "r") as f:
            log_content = f.read()
        log_window = tk.Toplevel(self.root)
        log_window.title("Activity Log")
        log_window.geometry("600x400")
        log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, font=("Consolas", 10))
        log_text.pack(expand=True, fill="both")
        log_text.insert("1.0", log_content)
        log_text.config(state="disabled")

    def clear_log(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear the log?"):
            open("activity.log", "w").close()
            messagebox.showinfo("Info", "Log cleared successfully.")

    def clear_encrypted_file(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear encrypted.txt?"):
            open("encrypted.txt", "w").close()
            messagebox.showinfo("Info", "encrypted.txt cleared successfully.")

if __name__ == "__main__":
    root = tk.Tk()
    app = TextEncrypterApp(root)
    root.mainloop()
