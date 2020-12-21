# Python imports
import os
import sys

# Crypto imports
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Custom imports
import db

DATABASE = "%s/database" % os.getcwd()

def auth(user, pwd):
    # Check user exists
    if not db.get_valid_user(user):
        print("Invalid user")
        return None,
    # Get password from db
    password = db.get_password(user)

    # Check if password is correct
    if password != pwd:
        print("Bad password")
        return None
    else:
        print("Generating session key...")
        # Generate session key
        key = __generate_key()
        
        # Save session key to user
        try:
            print("Saving session key to user...")
            with open("%s/users/%s/keys/session_key.key" % (DATABASE, user), "wb") as f:
                f.write(key)
                f.close()
        except:
            print("Error saving session key")
            print(sys.exc_info())
            return None

        return key.decode('utf-8')

def encryptRSA(user, msg):
    # Get user RSA key
    try:
        with open("%s/users/%s/publicKey.pem" % (DATABASE, user), "rb") as f:
            pKey = serialization.load_pem_public_key(f.read(), backend=default_backend())
            f.close()
    except FileNotFoundError:
        print("No public RSA key found.")
        return None
    
    return pKey.encrypt(
        msg.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def __generate_key():
    return Fernet.generate_key()