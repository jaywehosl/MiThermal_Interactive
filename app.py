# app.py
import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import io

# --- Core Encryption/Decryption Logic (from your script) ---

# Key and IV are hardcoded as per the original script's requirement
KEY = b'thermalopenssl.h'
IV = b'thermalopenssl.h'

def decrypt_data(ciphertext: bytes) -> bytes:
    """Decrypts the given ciphertext using AES-128-CBC."""
    try:
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
    except ValueError:
        # This will catch errors from incorrect padding, often meaning a wrong key or corrupted file
        return None

def encrypt_data(plaintext: bytes) -> bytes:
    """Encrypts the given plaintext using AES-128-CBC."""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# --- Streamlit Web App Interface ---

st.set_page_config(page_title="MiThermal Editor", layout="centered")

st.title("MiThermal Interactive Editor")
st.markdown("Внимание! Все изменения пар target-trig (частота-температура) вы делаете только на свой риск.")

# Initialize session state to hold the data between reruns
if 'decrypted_text' not in st.session_state:
    st.session_state.decrypted_text = ""
if 'original_filename' not in st.session_state:
    st.session_state.original_filename = "encrypted.conf"

# --- Step 1: File Upload ---
st.header("")
uploaded_file = st.file_uploader("", type=['conf'])

if uploaded_file is not None:
    # Store the filename for the final download
    st.session_state.original_filename = uploaded_file.name
    
    # Decrypt button
    if st.button("Дешифровать файл"):
        # Read file content as bytes
        ciphertext = uploaded_file.getvalue()
        plaintext_bytes = decrypt_data(ciphertext)
        
        if plaintext_bytes:
            # On success, store the decoded text in session state
            # Use 'latin-1' or 'utf-8' with error handling, as config files can have mixed encodings
            st.session_state.decrypted_text = plaintext_bytes.decode('latin-1')
            st.success("Дешифровка успешна. Содержимое доступно в редакторе ниже.")
        else:
            st.error("Ошибка дешифровки! Возможно, ваш файл устаревший или имеет неверный формат/ключ шифрования")
            st.session_state.decrypted_text = "" # Clear any old text

# --- Step 2: Edit Text Area ---
if st.session_state.decrypted_text:
    st.header("")
    
    # The text_area's content is now managed by session_state
    edited_text = st.text_area(
        "Значения таблиц [XXXX-SS-CPU] = target (частота) задаётся в Герцах (2.5ГГц=2500000Гц), значение trig (порог температуры) задаётся в градусах Цельсия, умноженных на 1000 (48000=48С*1000):",
        value=st.session_state.decrypted_text,
        height=400,
        key="editor" # Give it a key to easily access its current value
    )
    
    st.header("")
    
    # --- Step 3: Encrypt and Download Button ---
    if edited_text:
        # Encode the edited text back to bytes
        final_plaintext_bytes = edited_text.encode('latin-1')
        
        # Encrypt the final data
        final_ciphertext = encrypt_data(final_plaintext_bytes)
        
        # Provide the download button
        st.download_button(
            label="Сохранить .conf файл",
            data=final_ciphertext,
            file_name=f"edited_{st.session_state.original_filename}",
            mime="application/octet-stream" # A generic mime type for binary files
        )
