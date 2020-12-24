"""Contains all methods relating to communicating with the database"""

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import json
import os
import time
import sys

import crypto

DATABASE = "%s/database" % os.getcwd()

def get_valid_user(user):
    """Checks if this user exists

            Parameters:
                user (str): User to look for

            Returns:
                True (bool) if found, False if not
    """
    # Get files in database
    files = os.listdir("%s/users" % DATABASE)

    # Check if user exists
    return user in files

def get_password(user):
    """Get user's password from database

            Parameters:
                user (str): User to look for password under

            Returns:
                Password (str) if found, None if user doesn't exist
    """
    # Check user exists
    try:
        with open("%s/users/%s/userInfo.json" % (DATABASE, user), "r") as f:
            userData = json.load(f)
            f.close()
    except FileNotFoundError:
        raise "User does not exist"
    
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
        with open("%s/users/%s/publicKey.pem" % (DATABASE, user), "rb") as f:
            userKey = serialization.load_pem_public_key(f.read(), backend=default_backend())
            f.close()
    except FileNotFoundError:
        return None
    
    return userKey

def post_file(user_to, file, key):
    pass

def create_user(user, pwd):
    """Creates user in database

            Parameters:
                user (str): username
                pwd (str): password

            Returns:
                True if successful, False if not
    """
    # Create user directory
    try:
        os.mkdir("{db}/users/{user}".format(db=DATABASE, user=user))
    except:
        # Any errors, return false
        print("Error creation user directory")
        return False

    # Create keys directory
    try:
        os.mkdir("{db}/users/{user}/keys".format(db=DATABASE, user=user))
    except:
        print("Error creating keys directory")
        return False
    
    # Load user masterfile
    try:
        with open("{db}/users/masterfile.json".format(db=DATABASE), "r") as f:
            masterList = json.loads(f.read())
            f.close()
    except:
        print("Error opening master list")
        return False

    # Hash user's password
    hPwd, salt = crypto.hash_password(pwd)

    # Add user's info to masterlist
    masterList[user] = {
        "pwd": hPwd,
        "salt": salt,
        "creation": time.asctime()
    }

    # Save user data
    try:
        with open("{db}/users/masterfile.json".format(db=DATABASE, user=user), "w") as f:
            json.dump(masterList, f)
            f.close()
    except:
        print("Error saving user information")
        print(sys.exc_info())
        return False

    # Success!
    return True

def update_key(user, key):
    # Check if user's key bytes or RSAPublicKey
    if type(key) is bytes:
        keyPem = key
    else:
        # Serialize user's public key
        keyPem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    try:
        with open("{db}/users/{user}/publicKey.pem".format(db=DATABASE, user=user), "wb") as f:
            f.write(keyPem)
            f.close()
    except:
        # Any errors return false
        print("Error saving user's public key")
        return False
    
    print("Key written")
    return True

def post_session_key(user, key):
    pass

def update_password(user, pwd):
    pass