from cryptography.hazmat.primitives.asymmetric import rsa, padding

from cryptography.hazmat.primitives import serialization, hashes

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair():

    private_key = rsa.generate_private_key(

        public_exponent=65537,

        key_size=2048,

        backend=default_backend()

    )

    public_key = private_key.public_key()

    return (

        public_key.public_bytes(

            encoding=serialization.Encoding.PEM,

            format=serialization.PublicFormat.SubjectPublicKeyInfo

        ),

        private_key.private_bytes(

            encoding=serialization.Encoding.PEM,

            format=serialization.PrivateFormat.PKCS8,

            encryption_algorithm=serialization.NoEncryption()

        )

    )

def pem_encoding(key, filepath, filename):

    if not filename.endswith(".pem"):

        raise Exception("Only pem encoding is allowed")

    with open(filepath, "wb") as f:

        f.write(key)

def read_pem_encoding(filepath):

    with open(filepath, "rb") as f:

        return serialization.load_pem_private_key(

            f.read(),

            password=None,

            backend=default_backend()

        )

def rsa_encrypt(public_key, plaintext):

    if not isinstance(plaintext, bytes):

        plaintext = plaintext.encode("utf-8")

    public_key = serialization.load_pem_public_key(

        public_key,

        backend=default_backend()

    )

    ciphertext = public_key.encrypt(

        plaintext,

        padding.OAEP(

            mgf=padding.MGF1(algorithm=hashes.SHA256()),

            algorithm=hashes.SHA256(),

            label=None

        )

    )

    return ciphertext

def rsa_decrypt(private_key, ciphertext):

    private_key = serialization.load_pem_private_key(

        private_key,

        password=None,

        backend=default_backend()

    )

    plaintext = private_key.decrypt(

        ciphertext,

        padding.OAEP(

            mgf=padding.MGF1(algorithm=hashes.SHA256()),

            algorithm=hashes.SHA256(),

            label=None

        )

    )

    return plaintext

