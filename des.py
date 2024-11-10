from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def adjust_key(key_str, required_bytes=8):
    key_bytes = key_str.encode('utf-8')
    if len(key_bytes) < required_bytes:
        # Agregar bytes aleatorios para completar el tamaño
        extra_bytes = get_random_bytes(required_bytes - len(key_bytes))
        key_bytes += extra_bytes
    elif len(key_bytes) > required_bytes:
        # Truncar la clave
        key_bytes = key_bytes[:required_bytes]
    return key_bytes

def adjust_iv(iv_str, required_bytes=8):
    iv_bytes = iv_str.encode('utf-8')
    if len(iv_bytes) < required_bytes:
        # Agregar bytes aleatorios para completar el tamaño
        extra_bytes = get_random_bytes(required_bytes - len(iv_bytes))
        iv_bytes += extra_bytes
    elif len(iv_bytes) > required_bytes:
        # Truncar el IV
        iv_bytes = iv_bytes[:required_bytes]
    return iv_bytes

def des_encrypt(plaintext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext

def des_decrypt(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_padded_text = cipher.decrypt(ciphertext)
    decrypted_text = unpad(decrypted_padded_text, DES.block_size)
    return decrypted_text.decode('utf-8')

# Modo de prueba automático (comentar para usar)
"""
def test_des():
    plaintext = "Mensaje de prueba para DES"
    key_input = "claveDES"
    iv_input = "ivDES"

    key = adjust_key(key_input)
    iv = adjust_iv(iv_input)

    print(f"Clave DES ajustada: {key.hex()}")

    ciphertext = des_encrypt(plaintext, key, iv)
    print(f"Texto cifrado DES: {ciphertext.hex()}")

    decrypted_text = des_decrypt(ciphertext, key, iv)
    print(f"Texto descifrado DES: {decrypted_text}")

# test_des()
"""
