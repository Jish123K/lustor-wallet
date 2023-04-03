import hashlib

import secrets

from cryptography.hazmat.primitives import hashes, serialization

from cryptography.hazmat.primitives.asymmetric import rsa, padding

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def create_new_user(email, password):

    # Step 1: Generate a secret

    secret = password.encode() + email.encode()

    # Step 2: Generate an encryption key

    encryption_key = secrets.token_bytes(32)

    # Step 3: Encrypt the encryption key

    kdf = PBKDF2HMAC(

        algorithm=hashes.SHA256(),

        length=32,

        salt=email.encode(),

        iterations=100_000

    )

    password_derived_key = kdf.derive(secret)

    iv = secrets.token_bytes(16)

    cipher = Cipher(algorithms.AES(password_derived_key), modes.CBC(iv))

    encryptor = cipher.encryptor()

    encrypted_encryption_key = encryptor.update(encryption_key) + encryptor.finalize()

    # Step 4: Hash the password

    password_hash = hashlib.pbkdf2_hmac(

        "sha256",

        password.encode(),

        password_derived_key,

        1,

        dklen=64

    )

    # Step 5: Generate a forgot password hash

    password_derived_key_hash = hashlib.sha512(password_derived_key).hexdigest()

    # Step 6: Generate and encrypt an asymmetric key pair

    private_key = rsa.generate_private_key(

        public_exponent=65537,

        key_size=2048

    )

    public_key = private_key.public_key()

    encrypted_private_key = public_key.encrypt(

        private_key.private_bytes(

            encoding=serialization.Encoding.PEM,

            format=serialization.PrivateFormat.PKCS8,

            encryption_algorithm=serialization.NoEncryption()

        ),

        padding.OAEP(

            mgf=padding.MGF1(algorithm=hashes.SHA1()),

            algorithm=hashes.SHA1(),

            label=None

        )

    )

    return {

        "KDF": "PBKDF2",

        "iterations": 100_000,

        "email": email,

        "passwordHash": password_hash.hex(),

        "passwordDerivedKeyHash": password_derived_key_hash,

        "encryptedEncryptionKey": encrypted_encryption_key.hex(),

        "asymmetricPublicKey": public_key.public_bytes(

            encoding=serialization.Encoding.PEM,

            format=serialization.PublicFormat.SubjectPublicKeyInfo

        ).hex(),

        "encryptedAsymmetricPrivateKey": encrypted_private_key.hex()

    }

