"""Contains all methods relating to communicating with the database"""

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import json
import os

def get_password(user):
    """Get user's password from database

            Parameters:
                user (str): User to look for password under

            Returns:
                Password (str) if found, None if user doesn't exist
    """
    # Check user exists
    try:
        with open("%s/database/users/%s/userInfo.json" % (os.getcwd(), user), "r") as f:
            userData = json.load(f)
            f.close()
    except FileNotFoundError:
        return None
    
    # Return password
    return userData["password"]

def get_user_key(user):
    """Get user's public rsa key from database

            Parameters:
                user (str): User to look for password under

            Returns:
                RSA key if found, None if user doesn't exist
    """
    # Check user exists
    try:
        with open("%s/database/users/%s/publicKey.pem" % (os.getcwd(), user), "rb") as f:
            userKey = serialization.load_pem_public_key(f.read(), backend=default_backend())
            f.close()
    except FileNotFoundError:
        return None
    
    return userKey

def post_file(user_to, file, key):
    pass