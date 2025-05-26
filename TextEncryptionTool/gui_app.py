import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.fernet import Fernet
import os
import logging

# Logging setup
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

    def load_key(self):
        return open(self.key_file, "rb").read()

    def encrypt(self, text):
        encrypted = self.cipher.encrypt(text.encode()).decode()
        with open("encrypted.txt", "w") as f:
            f.write(encrypted)
        logging.info("Encrypted text: " + encrypted)
        return encrypted

    def decrypt(self, text):
        try:
            decrypted = self.cipher.decrypt(text.encode()).decode()
            logging.info("Decrypted text: " + decrypted)
            return decrypted
        except Exception as e:
            logging.warning(f"Failed to decrypt: {text} | Error: {e}")
            return "❌ Decryption Failed."

class TextEncrypterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Text Encryption Tool")
        self.root.geometry("600x400")
        self.root.resizable(False, False)

        self.encryptor = TextEncryptor()

        self._create_widgets()
        self._layout_widgets()

    def _create_widgets(self):
        # Labels
        self.input_label = tk.Label(self.root, text="Enter Text:")
        self.result_label = tk.Label(self.root, text="Output:")

        # Text areas
        self.input_text = scrolledtext.ScrolledText(self.root, height=5)
        self.result_text = scrolledtext.ScrolledText(self.root, height=5, state='disabled')

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
        if not plain:
            messagebox.showwarning("Input Error", "Enter text to encrypt.")
            return
        encrypted = self.encryptor.encrypt(plain)
        self._update_result_text(encrypted)
        messagebox.showinfo("Success", "Encrypted and saved to encrypted.txt.")

    def decrypt_action(self):
        encrypted = self.input_text.get("1.0", tk.END).strip()
        if not encrypted:
            messagebox.showwarning("Input Error", "Enter encrypted text to decrypt.")
            return
        decrypted = self.encryptor.decrypt(encrypted)
        self._update_result_text(decrypted)

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
            messagebox.showerror("Error", "No activity.log file found.")
            return
        try:
            with open("activity.log", "r") as log_file:
                log_content = log_file.read()
            log_window = tk.Toplevel(self.root)
            log_window.title("Activity Log")
            log_window.geometry("600x400")
            log_text = scrolledtext.ScrolledText(log_window)
            log_text.pack(expand=True, fill='both')
            log_text.insert(tk.END, log_content)
            log_text.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open log file: {e}")

    def clear_log(self):
        try:
            with open("activity.log", "w") as log_file:
                log_file.write("")
            messagebox.showinfo("Cleared", "activity.log has been cleared.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear log: {e}")

    def clear_encrypted_file(self):
        try:
            with open("encrypted.txt", "w") as enc_file:
                enc_file.write("")
            messagebox.showinfo("Cleared", "encrypted.txt has been cleared.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear encrypted file: {e}")

    def _update_result_text(self, text):
        self.result_text.config(state='normal')
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, text)
        self.result_text.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = TextEncrypterApp(root)
    root.mainloop()