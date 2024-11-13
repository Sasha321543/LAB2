from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

def generate_aes_key_iv(password: bytes, salt: bytes):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(password)
    iv = os.urandom(16)
    return key, iv

def aes_encrypt(input_file: str, output_file: str, password: bytes):
    salt = os.urandom(16)
    key, iv = generate_aes_key_iv(password, salt)
    with open(input_file, 'rb') as f:
        data = f.read()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + b"\0" * (16 - len(data) % 16)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    mac = h.finalize()
    with open(output_file, 'wb') as f:
        f.write(salt + iv + mac + encrypted_data)

def aes_decrypt(input_file: str, output_file: str, password: bytes):
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        mac = f.read(32)
        encrypted_data = f.read()
    key, _ = generate_aes_key_iv(password, salt)
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    h.verify(mac)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    data = padded_data.rstrip(b"\0")
    with open(output_file, 'wb') as f:
        f.write(data)

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(data: bytes, public_key):
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(encrypted_data: bytes, private_key):
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def generate_password(length):
    chars = r'!\"#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
    from os import urandom
    return "".join(chars[c % len(chars)] for c in urandom(length))

def sign_file(input_file: str, private_key):
    # Завантаження даних файлу
    with open(input_file, "rb") as f:
        data = f.read()
    # Створення підпису
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(input_file: str, signature: bytes, public_key):
    # Завантаження даних файлу
    with open(input_file, "rb") as f:
        data = f.read()
    # Перевірка підпису
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto Application")
        self.encrypt_btn = tk.Button(root, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_btn.pack()
        self.decrypt_btn = tk.Button(root, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_btn.pack()
        # Кнопка для генерації RSA ключів
        self.generate_rsa_btn = tk.Button(root, text="Generate RSA Keys", command=self.generate_rsa_keys)
        self.generate_rsa_btn.pack()
        self.sign_btn = tk.Button(root, text="Sign File", command=self.sign_file)
        self.sign_btn.pack()
        self.verify_btn = tk.Button(root, text="Verify Signature", command=self.verify_file)
        self.verify_btn.pack()
        self.password_label = tk.Label(root, text="Enter Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

    def encrypt_file(self):
        input_file = filedialog.askopenfilename(title="Select file to encrypt")
        if not input_file:return
        output_file = filedialog.asksaveasfilename(title="Save encrypted file as")
        if not output_file:return
        choice = messagebox.askyesno("Encryption Choice", "Would you like to encrypt with RSA key? (Yes for RSA, No for AES with password)")
        if choice:
            # RSA Encryption
            public_key_file = filedialog.askopenfilename(title="Select RSA Public Key")
            if not public_key_file:return
            with open(public_key_file, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
            with open(input_file, "rb") as f:
                data = f.read()
            encrypted_data = rsa_encrypt(data, public_key)
            with open(output_file, "wb") as f:
                f.write(encrypted_data)
            messagebox.showinfo("Success", "File encrypted with RSA successfully!")
        else:
            password = generate_password(10)
            with open('generated_password.txt', "w+") as f:
                f.write(password)
                aes_encrypt(input_file, output_file, bytes(password,'UTF-8'))
                messagebox.showinfo("Success", "File encrypted successfully!")

    def decrypt_file(self):
        input_file = filedialog.askopenfilename(title="Select file to decrypt")
        if not input_file:return
        output_file = filedialog.asksaveasfilename(title="Save decrypted file as")
        if not output_file:return
        choice = messagebox.askyesno("Decryption Choice", "Was the file encrypted with RSA? (Yes for RSA, No for AES with password)")
        if choice:
            # RSA Decryption
            private_key_file = filedialog.askopenfilename(title="Select RSA Private Key")
            if not private_key_file:return
            with open(private_key_file, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            with open(input_file, "rb") as f:
                encrypted_data = f.read()
            data = rsa_decrypt(encrypted_data, private_key)
            with open(output_file, "wb") as f:
                f.write(data)
            messagebox.showinfo("Success", "File decrypted with RSA successfully!")
        else:
            # AES Decryption
            password = self.password_entry.get().encode()
            aes_decrypt(input_file, output_file, password)
            messagebox.showinfo("Success", "File decrypted with AES successfully!")

    def sign_file(self):
        input_file = filedialog.askopenfilename(title="Select file to sign")
        if not input_file:return
        private_key_file = filedialog.askopenfilename(title="Select RSA Private Key")
        if not private_key_file:return
        signature_file = filedialog.asksaveasfilename(title="Save signature as")
        if not signature_file:return
        # Завантаження приватного ключа
        with open(private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        # Підпис файлу
        signature = sign_file(input_file, private_key)
        # Збереження підпису
        with open(signature_file, "wb") as f:
            f.write(signature)
        messagebox.showinfo("Success", "File signed successfully!")

    def verify_file(self):
        input_file = filedialog.askopenfilename(title="Select file to verify")
        if not input_file:return
        signature_file = filedialog.askopenfilename(title="Select signature file")
        if not signature_file:return
        public_key_file = filedialog.askopenfilename(title="Select RSA Public Key")
        if not public_key_file:return
        # Завантаження публічного ключа
        with open(public_key_file, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        # Завантаження підпису
        with open(signature_file, "rb") as f:
            signature = f.read()
        # Перевірка підпису
        is_valid = verify_signature(input_file, signature, public_key)
        if is_valid:
            messagebox.showinfo("Success", "Signature is valid!")
        else:
            messagebox.showerror("Error", "Signature is invalid!")

    def generate_rsa_keys(self):
        private_key, public_key = generate_rsa_keys()
        output_file = filedialog.asksaveasfilename(title="Save keys with base name")
        base_name, ext = os.path.splitext(output_file)
        private_key_file = base_name + ".pem"
        public_key_file = base_name + ".pub"
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(public_key_file, "wb") as f:
            f.write(pem_public)
        with open(private_key_file, "wb") as f:
            f.write(pem_private)
        messagebox.showinfo("RSA Keys", "RSA keys generated successfully!")
        # Можна зберегти ключі у файли чи показати їх
root = tk.Tk()
app = CryptoApp(root)
root.mainloop()