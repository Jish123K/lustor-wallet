from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import padding

from cryptography.hazmat.backends import default_backend

def aes_encrypt(key, plaintext):

    if isinstance(plaintext, str):

        plaintext = plaintext.encode()

    backend = default_backend()

    cipher = Cipher(algorithms.AES(key), modes.GCM())

    encryptor = cipher.encryptor()

    ct = encryptor.update(plaintext) + encryptor.finalize()

    return ct + encryptor.tag + encryptor.nonce

def aes_decrypt(key, ciphertext):

    backend = default_backend()

    cipher = Cipher(algorithms.AES(key), modes.GCM(ciphertext[-16:]), backend=backend)

    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext[:-32]) + decryptor.finalize()

    return plaintext

def aes_encrypt_CBC(key, plaintext):

    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    if isinstance(plaintext, str):

        plaintext = plaintext.encode()

    padded_plaintext = padder.update(plaintext) + padder.finalize()

    iv = os.urandom(algorithms.AES.block_size)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext + iv

def aes_decrypt_CBC(key, ciphertext):

    iv = ciphertext[-algorithms.AES.block_size:]

    ciphertext = ciphertext[:-algorithms.AES.block_size]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    decryptor = cipher.decryptor()

    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

    return plaintext

