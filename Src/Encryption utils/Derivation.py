import os

import hashlib

import binascii

from loguru import logger

N = 2**16  # Meant for RAM

R = 10

P = 10

def generate_scrypt_key(password, salt, key_length):

    """Generate a scrypt key from the given password and salt.

    Returns a tuple containing the hex-encoded salt and the key bytes.

    """

    logger.debug(f"Generating scrypt key with {password} and salt {salt}, with keylength {N}, R {R} and p {P}")

    if isinstance(password, str):

        password = password.encode()

    if isinstance(salt, str):

        salt = salt.encode()

    # Use hashlib to perform the scrypt key derivation.

    dk = hashlib.scrypt(

        password=password,

        salt=salt,

        n=N,

        r=R,

        p=P,

        dklen=key_length

    )

    # Return the salt as hex-encoded bytes and the derived key bytes.

    return binascii.hexlify(salt), dk

