##script to encrypt token
import os
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import base64
import boto3

key_id = 'arn:aws:kms:xxxxxxx:key/xxxxxxxxxxxxxxxxxxxx'
master_key = 'This is a secret key'
region_name = 'xx-xxxx-1'


def pad(st):
    """
    Function for padding string into block size of 16 for cryptographic functions. Returns padded string.

    :st: String to padd

    """
    block_size = 16
    padded_st = st + (block_size - len(st) % block_size) * chr(block_size -len(st) % block_size)
    return padded_st

def generate_key_from_KMS(master_key):
    """
    Function for encrypting the key and retrieving encrypted master key from KMS. Returns Encrypted master key.

    :master_key: Master key( to be provided by user to encrypt the data). This key can be deleted later on for purpose of security.

    The master key returned can be used for decrypting the data
    """
    kms = boto3.client('kms')
    try:
        response = kms.encrypt(
            KeyId=key_id,
            Plaintext=master_key,
            region_name=region_name
        )
        print "Encrypted master key: {}".format(response['CiphertextBlob'])
        print "Store the Encrypted master key. Can be used later on."
        return response["CiphertextBlob"]
    except Exception as e:
        print "[ERROR]: Error during KMS calls: {}".format(e)
        return

def encrypt_data(master_key, data):
    """
    Function for encrypting the data from the master key. Returns encrypted data.

    :master_key: Master key( to be provided by user to encrypt the data). This key can be deleted later on for purpose of security.
    :data: Data to be encrypted

    """
    tokens = []

    try:
        hashed_key = hashlib.sha256(master_key.encode("utf-8")).digest()
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(hashed_key, AES.MODE_CBC, iv)
        encrypted_tokens = []
        padded_token = pad(token)
        return base64.b64encode(iv + cipher.encrypt(padded_token))

    except Exception as e:
        print "[ERROR]: Error while data encryption: {}".format(e)
        return
        
    