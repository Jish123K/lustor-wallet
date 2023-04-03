import httpx

import binascii

from loguru import logger

from bcrypt import hashpw, gensalt

from pywallet import wallet

from pprint import pprint

from create_user import create_new_user

from settings import *

ID_TOKEN = ""

ENCRYPTION_KEY = ""

PASSWORD_DERIVED_KEY = ""

ASYMMETRIC_PRIVATE_KEY = ""

async def signup():

    data = {"username": "testUser", "password": "YOLOjedi98876$%", "email": "saurav@lexim.gold", "name": "First Jedi"}

    async with httpx.AsyncClient() as client:

        response = await client.post(URL_SIGNUP, json=data)

        if not response.status_code == 200:

            logger.error(response.text)

            return

    result = response.json()

    logger.success(result)

    return

async def confirm_sign_up(username, email, password, registration_code):

    """

    At this point, you must have received a registration code on your email after a successful signup operation,

    This function will confirm your signup on AWS cognito and update your details in DynamoDB

    necessary for your wallet

    """

    user = create_new_user(email, password)

    user.update({"username": username, "code": registration_code})

    async with httpx.AsyncClient() as client:

        response = await client.post(URL_CONFIRM_SIGNUP, json=user)

        if not response.status_code == 200:

            logger.error(response.text)

            return

    result = response.json()

    logger.success(result)

    return

async def login(username, password):

    async with httpx.AsyncClient() as client:

        response = await client.post(URL_LOGIN, json={'username': username, "password": password})

        result = response.json()

        logger.debug(result)

        global ID_TOKEN

        ID_TOKEN = result["data"]["id_token"]

    return result

def generate_password_hash(email, password):

    global PASSWORD_DERIVED_KEY

    PASSWORD_DERIVED_KEY = hashpw(password.encode(), gensalt(N))

    passwordHash = hashpw(PASSWORD_DERIVED_KEY, PASSWORD_DERIVED_KEY + password.encode(), rounds=10)

    return passwordHash.hex()

async def password_hash_login(username, password_hash):

    """

    The Client runs the AES-CBC de-cryption algorithm, with the encryptedEncryptionKey as the ciphertext, the IV and

    the passwordDerivedKey as the secret, returning the plaintext encryptionKey . The

    Client runs the AES-CBC decryption algorithm, with the encryptedAsymmetricPri-

    vateKey as the ciphertext, the IV and the encryptionKey as the secret, returning

    the plaintext asymmetricPrivateKey . The asymmetricPrivateKey is never stored

    in a persistent manner and only exists inside the browser’s process memory,

    """

    async with httpx.AsyncClient(headers={"Authorization": ID_TOKEN}) as client:

        response = await client.post(URL_PASSWORDHASH_LOGIN, json={'username': username, "passwordHash": password_hash})

        result = response.json()

        logger.debug(result)

        encryptedEncryptionKey = result["data"]["encryptedEncryptionKey"]

        global ENCRYPTION_KEY, ASYMMETRIC_PRIVATE_KEY

        ENCRYPTION_KEY = aes_decrypt_CBC(PASSWORD_DERIVED_KEY, binascii.unhexlify(encryptedEncryptionKey))

        encryptedAsymmetricPrivateKey = result["data"]["encryptedAsymmetricPrivateKey"]

        ASYMMETRIC_PRIVATE_KEY = aes_decrypt_CBC(ENCRYPTION_KEY, binascii.unhexlify(encryptedAsymmetricPrivateKey))

    return result

async def wallet_creation(username):
    global ASYMMETRIC_PRIVATE_KEY

    # Generate a new random seed and use it to create a new HD wallet
    seed = wallet.generate_mnemonic()
    w = wallet.create_wallet(network="BTC", seed=seed, children=1)

    # Encrypt the seed using the asymmetric private key
    encrypted_seed = rsa_encrypt(w.seed(), ASYMMETRIC_PRIVATE_KEY)

    # Create a new wallet record in DynamoDB
    wallet_data = {
        "username": username,
        "encryptedSeed": binascii.hexlify(encrypted_seed).decode(),
        "xpub": w.serialize_b58(private=False),
        "timestamp": int(time.time()),
    }
    async with httpx.AsyncClient(headers={"Authorization": ID_TOKEN}) as client:
        response = await client.post(URL_CREATE_WALLET, json=wallet_data)
        result = response.json()
        if not response.status_code == 200:
            logger.error(result)
            return
    logger.success(result)

    # Print out the wallet details
    pprint({
        "seed": seed,
        "encrypted_seed": binascii.hexlify(encrypted_seed).decode(),
        "xpub": w.serialize_b58(private=False),
    })
async def get_wallet(username):

    async with aiohttp.ClientSession(headers={"Authorization": ID_TOKEN}) as session:

        response = await session.post(URL_GET_WALLET, json={"username": username})

        if response.status != 200:

            logger.error(f"Failed to get wallet: {response.reason}")

            return

        result = await response.json()

        encrypted_mnemonic_phrase = result["data"].get("encryptedMnemonicPhrase")

        if encrypted_mnemonic_phrase:

            decrypted_mnemonic_phrase = aes_decrypt_CBC(ENCRYPTION_KEY, binascii.unhexlify(encrypted_mnemonic_phrase))

            logger.success(f"User Mnemonic Phrase is {decrypted_mnemonic_phrase}")

        else:

            encrypted_private_key = result["data"].get("encryptedPrivateKey")

            if encrypted_private_key:

                decrypted_private_key = aes_decrypt_CBC(ENCRYPTION_KEY, binascii.unhexlify(encrypted_private_key))

                logger.success(f"User Private Key is {decrypted_private_key}")

            else:

                logger.error("Failed to get wallet: encryptedMnemonicPhrase and encryptedPrivateKey not found in response")

                return



