# Python imports
from binascii import a2b_base64
import os
import time
import base64

# Custom imports
import src.db as db
import src.crypto as crypto
from src.packet import Packet

def auth(connection, reqPack):
    # Get important fields
    # Format: <username>,<password>
    user = reqPack.get_fields(0)
    pwd = reqPack.get_fields(1)
    
    # First check if user exists
    if not db.get_valid_user(user):
        print("Invalid user")
        return False

    userData = db.get_user_info(user)
    
    # Check if passwords match
    if not compare_passwords(userData, pwd):
        print("Password error")
        respPack = Packet("AUTH", "DONE,ERR")
    
    # Create and save token
    token = generate_token(user, userData)

    if token is None:
        respPack = Packet("AUTH", "DONE,ERR")
    else:
        respPack = Packet("AUTH", "DONE,SUCC")
        
        # Encrypt token with session key
        key = crypto.generate_fernet()
        safeTok = crypto.encrypt_fernet(token, key)

        # Encrypt key with user's public key
        safeKey = crypto.encrypt_rsa(key, db.get_user_key(user))

        # Add token and key to packet
        respPack.add_encrypted(safeTok)
        respPack.add_encrypted(safeKey)

    # Send status
    print("Sending {packet}".format(packet=respPack.send().decode('utf-8')))
    connection.sendall(respPack.send())  

    # End of job, return
    return


def compare_passwords(user, pwd):
    # Get user's hash
    uHash = user["pwd"]

    # Get user salt
    salt = user["salt"]

    # Hash given password
    hPwd = crypto.hash_password(pwd, salt)[0]

    # Compare hashes
    return hPwd == uHash


def generate_token(user, user_data):
    # Generate 64 bit token
    token = os.urandom(64)

    # Base64 encode token
    asciiToken = base64.b64encode(token)

    # Turn into ascii
    asciiToken = asciiToken.decode('ascii')

    # Update info in user's information
    user_data["token"] = asciiToken
    user_data["token_valid_until"] = time.monotonic() + 86400  # Set token valid 1 day

    # Save info
    saved = db.update_user_info(user, user_data)
    
    if not saved:
        return None

    # Return token
    return token