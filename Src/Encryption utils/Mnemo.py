import hdwallet

import os

def generate_entropy(strength_bits=None):

    if not strength_bits:

        strength_bits = 256

    entropy = os.urandom(strength_bits // 8)

    return entropy

def generate_mnemonic(lang):

    ##lang in which the entropy must be generated

    entropy = generate_entropy()

    _mnemonic = hdwallet.generate_mnemonic(entropy, lang)

    return _mnemonic

def child_keys(mnemonic, index):

    seed = hdwallet.seed(mnemonic)

    master_key = hdwallet.from_seed(seed)

    child_key = hdwallet.from_path(master_key, f"m/44'/0'/{index}'/0/0")

    return {

        "private_key": child_key.private_key().hex(),

        "public_key": child_key.public_key().hex(),

        "address": hdwallet.pubkey_to_address(child_key.public_key())

    }

