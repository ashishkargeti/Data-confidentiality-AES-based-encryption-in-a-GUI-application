# Data-confidentiality-AES-based-encryption-in-a-GUI-application
#This project showcases the development of a Python-based desktop application that performs AES (Advanced Encryption Standard) encryption and decryption on text data through a #simple, clean, and responsive GUI built using Tkinter.

import tkinter as tk
from tkinter import *
from Crypto.Cipher import AES
import base64
import os

# Padding functions
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[:-ord(s[len(s)-1:])]

def encrypt(message, key):
    key = key.zfill(32)[:32]
    raw = pad(message).encode()
    iv = os.urandom(16)
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw)).decode()

def decrypt(enc, key):
    key = key.zfill(32)[:32]
    enc = base64.b64decode(enc)
    iv, cipher_bytes = enc[:16], enc[16:]
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_bytes).decode())

def encrypt_action():
    msg = text_box.get("1.0", END).strip()
    key = key_entry.get()
    result = encrypt(msg, key)
    result_box.delete("1.0", END)
    result_box.insert(END, result)

def decrypt_action():
    msg = text_box.get("1.0", END).strip()
    key = key_entry.get()
    try:
        result = decrypt(msg, key)
    except Exception as e:
        result = "Error: Invalid key or format"
    result_box.delete("1.0", END)
    result_box.insert(END, result)

# --- GUI Layout ---
root = Tk()
root.title("Secret Messenger")
root.geometry("400x500")

Label(root, text="Message").pack()
text_box = Text(root, height=5)
text_box.pack()

Label(root, text="Key").pack()
key_entry = Entry(root, show="*")
key_entry.pack()

btn_frame = Frame(root)
btn_frame.pack(pady=10)

Button(btn_frame, text="Encrypt", command=encrypt_action).grid(row=0, column=0, padx=5)
Button(btn_frame, text="Decrypt", command=decrypt_action).grid(row=0, column=1, padx=5)

Label(root, text="Result").pack()
result_box = Text(root, height=5)
result_box.pack()

root.mainloop()
