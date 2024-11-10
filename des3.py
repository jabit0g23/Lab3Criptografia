from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def adjust_key(key_str, required_bytes=24):
    key_bytes = key_str.encode('utf-8')
    while True:
        if len(key_bytes) < required_bytes:
            # Agregar bytes aleatorios para completar el tamaño
            extra_bytes = get_random_bytes(required_bytes - len(key_bytes))
            key_bytes += extra_bytes
        elif len(key_bytes) > required_bytes:
            # Truncar la clave
            key_bytes = key_bytes[:required_bytes]
        try:
            # Validar clave correcta para DES3
            DES3.new(key_bytes, DES3.MODE_CBC, iv=b'12345678')
            break
        except ValueError:
            # Si la clave no es válida, agregar un byte aleatorio
            key_bytes = key_bytes[:-1] + get_random_bytes(1)
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

def des3_encrypt(plaintext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_text = pad(plaintext.encode('utf-8'), DES3.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext

def des3_decrypt(ciphertext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_padded_text = cipher.decrypt(ciphertext)
    decrypted_text = unpad(decrypted_padded_text, DES3.block_size)
    return decrypted_text.decode('utf-8')

# Modo de prueba automático (comentar para usar)
"""
def test_des3():
    plaintext = "Mensaje de prueba para 3DES"
    key_input = "clave3DES"
    iv_input = "iv3DES"

    key = adjust_key(key_input)
    iv = adjust_iv(iv_input)

    print(f"Clave 3DES ajustada: {key.hex()}")

    ciphertext = des3_encrypt(plaintext, key, iv)
    print(f"Texto cifrado 3DES: {ciphertext.hex()}")

    decrypted_text = des3_decrypt(ciphertext, key, iv)
    print(f"Texto descifrado 3DES: {decrypted_text}")

# test_des3()
"""
