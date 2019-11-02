from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from os import urandom
import pytz
import json
import base64

def gnerateCardDataJson(name, pan, cvc, expiry_month, expiry_year):
    generation_time = datetime.now(tz=pytz.timezone('UTC')).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    return {
        "holderName": name,
        "number": pan,
        "cvc": cvc,
        "expiryMonth": expiry_month,
        "expiryYear": expiry_year,
        "generationtime": generation_time
    }

def encryptWithAesKey(aes_key, nonce, plaintext):
    cipher = AESCCM(aes_key, tag_length=8)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return ciphertext

def decodeAdyenPublicKey(encoded_public_key):
    backend = default_backend()
    key_components = encoded_public_key.split("|")
    public_number = rsa.RSAPublicNumbers(int(key_components[0], 16), int(key_components[1], 16))
    return backend.load_rsa_public_numbers(public_number)

def encryptWithPublicKey(public_key, plaintext):
    ciphertext = public_key.encrypt(plaintext, padding.PKCS1v15())
    return ciphertext

def main(name, pan, cvc, expiry_month, expiry_year, key):

    plainCardData = gnerateCardDataJson(
        name=name,
        pan=pan,
        cvc=cvc,
        expiry_month=expiry_month,
        expiry_year=expiry_year
    )

    cardDataJsonString = json.dumps(plainCardData, sort_keys=True)
    aesKey = AESCCM.generate_key(256)
    nonce = urandom(12)
    encryptedCardData = encryptWithAesKey(aesKey, nonce, bytes(cardDataJsonString, encoding='utf8'))
    encryptedCardComponent = nonce + encryptedCardData
    adyenPublicKey = key
    publicKey = decodeAdyenPublicKey(adyenPublicKey)
    encryptedAesKey = encryptWithPublicKey(publicKey, aesKey)
    encryptedAesData = "{}_{}${}${}".format("adyenjs","0_1_18", (base64.standard_b64encode(encryptedAesKey)).decode("utf-8") , (base64.standard_b64encode(encryptedCardComponent)).decode("utf-8"))

    return encryptedAesData