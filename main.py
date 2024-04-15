import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import logging

# Setup logging
logging.basicConfig(filename='log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def pad(data):
    """
    Pads the input data to be a multiple of 16 bytes.
    """
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data

def unpad(padded_data):
    """
    Removes padding from the decrypted data.
    """
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data)
    data += unpadder.finalize()
    return data

def double_encrypt(keys, plaintext):
    """
    Performs double encryption using AES and ChaCha20 algorithms with the provided keys.
    Returns the IV/Nonce and combined ciphertext separately.
    """
    aes_key, chacha_key = keys
    aes_iv = os.urandom(16)  # Generate a random 16-byte IV for AES

    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()
    aes_ciphertext = aes_encryptor.update(pad(plaintext)) + aes_encryptor.finalize()

    chacha_nonce = os.urandom(12)  # Generate a random 12-byte nonce for ChaCha20
    chacha_cipher = Cipher(algorithms.ChaCha20(chacha_key, chacha_nonce), mode=None, backend=default_backend())
    chacha_encryptor = chacha_cipher.encryptor()
    chacha_ciphertext = chacha_encryptor.update(aes_ciphertext) + chacha_encryptor.finalize()

    return aes_iv, chacha_nonce, chacha_ciphertext

def double_decrypt(keys, aes_iv, chacha_nonce, chacha_ciphertext):
    """
    Performs double decryption using AES and ChaCha20 algorithms with the provided keys, IV, and nonce.
    """
    aes_key, chacha_key = keys

    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    aes_decryptor = aes_cipher.decryptor()
    aes_ciphertext = aes_decryptor.update(chacha_ciphertext) + aes_decryptor.finalize()

    chacha_cipher = Cipher(algorithms.ChaCha20(chacha_key, chacha_nonce), mode=None, backend=default_backend())
    chacha_decryptor = chacha_cipher.decryptor()
    plaintext = chacha_decryptor.update(aes_ciphertext) + chacha_decryptor.finalize()

    return unpad(plaintext)

def display_algorithm_explanations():
    """
    Displays simple yet detailed explanations of algorithms and encryption/decryption terms.
    """
    print("\nAlgorithm Explanations:")
    print("1. AES (Advanced Encryption Standard) - A symmetric encryption algorithm widely used for securing sensitive data.")
    print("2. ChaCha20 - A stream cipher designed to provide high security and performance.")
    print("3. Initialization Vector (IV) - A random value used along with the key for encryption to ensure that "
          "the same plaintext doesn't encrypt to the same ciphertext every time.")
    print("4. Padding - Adding extra bytes to the plaintext before encryption to make its length a multiple of the block size.")
    print("5. CBC (Cipher Block Chaining) - A mode of operation for block ciphers that introduces feedback, making each "
          "plaintext block dependent on all previous ciphertext blocks.")
    print("6. ChaCha20 Nonce - A unique value used with the key to initialize the ChaCha20 cipher and ensure unique ciphertexts.")

def main():
    aes_key = os.urandom(32)  # Generate a random 32-byte AES key
    chacha_key = os.urandom(32)  # Generate a random 32-byte ChaCha20 key
    keys = (aes_key, chacha_key)

    print("Double Encryption/Decryption Interface")
    logging.info("Double Encryption/Decryption Interface Started")

    while True:
        print("\nMenu:")
        print("1. Encrypt - Encrypt a message using AES and ChaCha20 algorithms.")
        print("2. Decrypt - Decrypt a message previously encrypted with AES and ChaCha20.")
        print("3. Algorithm Explanations - View simple yet detailed explanations of algorithms and encryption/decryption terms.")
        print("4. Quit - Exit the program.")

        choice = input("Enter the number corresponding to your choice: ")

        if choice == '1':
            plaintext = input("Enter the text to encrypt: ").encode('utf-8')
            aes_iv, chacha_nonce, chacha_ciphertext = double_encrypt(keys, plaintext)
            print("\nDouble Encrypted Ciphertext (IV/Nonce, Ciphertext):")
            combined_data = aes_iv + chacha_nonce + chacha_ciphertext
            print("Combined Data:", urlsafe_b64encode(combined_data).decode('utf-8'))
            logging.info("Double Encrypted")
        elif choice == '2':
            combined_data = urlsafe_b64decode(input("Enter the IV/Nonce and ciphertext: "))
            aes_iv = combined_data[:16]
            chacha_nonce = combined_data[16:28]
            chacha_ciphertext = combined_data[28:]
            decrypted_text = double_decrypt(keys, aes_iv, chacha_nonce, chacha_ciphertext)
            print("\nDecrypted Text:", decrypted_text.decode('utf-8'))
            logging.info("Decrypted: " + decrypted_text.decode('utf-8'))
        elif choice == '3':
            display_algorithm_explanations()
        elif choice == '4':
            print("Exiting...")
            logging.info("Double Encryption/Decryption Interface Exited")
            break
        else:
            print("Invalid choice. Please enter a number from the menu.")

if __name__ == "__main__":
    main()
