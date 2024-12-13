import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

def generate_key():
    """Generate a 16-byte key for AES encryption."""
    return os.urandom(16)

def encrypt_value(value, key):
    """Encrypt a single value using AES."""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(value.encode(), AES.block_size))
    return b64encode(ct_bytes).decode('utf-8'), b64encode(cipher.iv).decode('utf-8')

def decrypt_value(ciphertext, iv, key):
    """Decrypt a single value using AES."""
    try:
        iv = b64decode(iv)
        ct = b64decode(ciphertext)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    except Exception as e:
        return f"Decryption failed: {str(e)}"

if "encrypted_data" not in st.session_state:
    st.session_state.encrypted_data = None
    st.session_state.iv_store = None
    st.session_state.key = None

st.title("AES Encryption/Decryption for Card Details")
st.markdown("This application encrypts and decrypts card details using AES.")

with st.form("card_form"):
    st.subheader("Enter Card Details")
    card_holder = st.text_input("Card Holder Name", max_chars=50)
    card_number = st.text_input("Card Number", max_chars=16, type="password")
    start_date = st.date_input("Start Date")
    end_date = st.date_input("End Date")
    cvv = st.text_input("CVV", max_chars=3, type="password")
    submitted = st.form_submit_button("Encrypt")

if submitted:
    if card_holder and card_number and start_date and end_date and cvv:
        key = generate_key()
        encrypted_data = {}
        iv_store = {}
        for field_name, field_value in [
            ("Card Holder Name", card_holder),
            ("Card Number", card_number),
            ("Start Date", str(start_date)),
            ("End Date", str(end_date)),
            ("CVV", cvv),
        ]:
            encrypted_value, iv = encrypt_value(field_value, key)
            encrypted_data[field_name] = encrypted_value
            iv_store[field_name] = iv

        st.session_state.encrypted_data = encrypted_data
        st.session_state.iv_store = iv_store
        st.session_state.key = key

        st.success("Encryption Successful!")
        st.json(encrypted_data)
    else:
        st.error("Please fill all the fields to proceed.")

# Decrypt Button
if st.session_state.encrypted_data:
    if st.button("Decrypt"):
        decrypted_data = {}
        for field_name, ciphertext in st.session_state.encrypted_data.items():
            decrypted_data[field_name] = decrypt_value(
                ciphertext,
                st.session_state.iv_store[field_name],
                st.session_state.key,
            )
        st.subheader("Decrypted Card Details")
        st.json(decrypted_data)
