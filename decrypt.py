##script to encrypt token
import os
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import base64
import boto3

region_name = 'xx-xxxx-1'

def unpad(st):
    """
    Function for unpadding strings. Returns unpadded data

    :st: String to unpad
    """
    unpadded_st = st[:-ord(st[len(st) - 1:])]
    return unpadded_st

def decrypt_data(encrypted_data):
    """
    Function for decrypting data. Returns the decrypted data. Returns decrypted data.

    :data: Data to be decrypted

    The current implementation uses KMS for retireiving key used for decryption and decrypts
    using AES 256. 
    """

    decryption_key = get_key_from_KMS()
    if not decryption_key:
        return
    try:
        private_key = hashlib.sha256(decryption_key.encode("utf-8")).digest()
        enc = base64.b64decode(encrypted_data)
        #initialization vector generation
        iv = encrypted_data[:16]
        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(enc[16:]))
        print "Data Decrypted: {}".format(decrypted_data)
        return decrypted_data
    except Exception as e:
        print "[ERROR] Error while decrypting the key: {}".format(e)
        return


def get_key_from_KMS():
    """
    Function for retriveing master key from KMS. Returns Plain

    The master key returned can be used for decrypting the data.
    """
    secret_key = os.environ('ENCRYPTED_MASTER_KEY')
    kms = boto3.client('kms', region_name=region_name)
    try:
        plain_text = kms.decrypt(
            CiphertextBlob=bytes(base64.b64decode(secret_key))
        )
        return base64.b64decode(plain_text['Plaintext'])
    except Exception as e:
        print "[ERROR]: Error while retriving master key from KMS: {}".format(e)
        return
