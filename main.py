from des import des_encrypt, des_decrypt, adjust_key as adjust_des_key, adjust_iv as adjust_des_iv
from des3 import des3_encrypt, des3_decrypt, adjust_key as adjust_des3_key, adjust_iv as adjust_des3_iv
from aes256 import aes_encrypt, aes_decrypt, adjust_key as adjust_aes_key, adjust_iv as adjust_aes_iv

def main():
    # Solicitar texto a cifrar
    plaintext = input("Ingrese el texto a cifrar: ")

    # DES
    print("\nCifrado DES:")
    des_key_input = input("Ingrese la clave DES: ")
    des_iv_input = input("Ingrese el IV DES: ")

    des_key = adjust_des_key(des_key_input)
    des_iv = adjust_des_iv(des_iv_input)

    print(f"Clave DES ajustada: {des_key.hex()}")

    des_ciphertext = des_encrypt(plaintext, des_key, des_iv)
    print(f"Texto cifrado DES: {des_ciphertext.hex()}")

    des_decrypted_text = des_decrypt(des_ciphertext, des_key, des_iv)
    print(f"Texto descifrado DES: {des_decrypted_text}")

    # 3DES
    print("\nCifrado 3DES:")
    des3_key_input = input("Ingrese la clave 3DES: ")
    des3_iv_input = input("Ingrese el IV 3DES: ")

    des3_key = adjust_des3_key(des3_key_input)
    des3_iv = adjust_des3_iv(des3_iv_input)

    print(f"Clave 3DES ajustada: {des3_key.hex()}")

    des3_ciphertext = des3_encrypt(plaintext, des3_key, des3_iv)
    print(f"Texto cifrado 3DES: {des3_ciphertext.hex()}")

    des3_decrypted_text = des3_decrypt(des3_ciphertext, des3_key, des3_iv)
    print(f"Texto descifrado 3DES: {des3_decrypted_text}")

    # AES-256
    print("\nCifrado AES-256:")
    aes_key_input = input("Ingrese la clave AES-256: ")
    aes_iv_input = input("Ingrese el IV AES-256: ")

    aes_key = adjust_aes_key(aes_key_input)
    aes_iv = adjust_aes_iv(aes_iv_input)

    print(f"Clave AES-256 ajustada: {aes_key.hex()}")

    aes_ciphertext = aes_encrypt(plaintext, aes_key, aes_iv)
    print(f"Texto cifrado AES-256: {aes_ciphertext.hex()}")

    aes_decrypted_text = aes_decrypt(aes_ciphertext, aes_key, aes_iv)
    print(f"Texto descifrado AES-256: {aes_decrypted_text}")

if __name__ == "__main__":
    main()
