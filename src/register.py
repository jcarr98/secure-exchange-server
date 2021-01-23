# Custom imports
import src.db as db
import src.crypto as crypto
from src.packet import Packet

def register(connection, data):
    # Data should be in format:
    # public_key, username, password
    # Where the public key is unencrypted, the username and password are encrypted with RSA public key
    parsedData = data.split(",".encode('utf-8'), 1)
    try:
        pKey = parsedData[0]
        uData = crypto.decrypt_rsa(parsedData[1])
    except IndexError:
        print("Invalid register packet length")
        return
    except ValueError:
        print("Error decoding username/password")
        return
    
    # Check username and password were included
    if len(uData.split(",")) != 2:
        print("No username or password")
        return

    # Create request packet
    reqPack = Packet("REGISTER", uData)
    reqPack.add_encrypted(pKey)

    # Request packet structure:
    # <username>,<password>,<public key>
    print("Attempting to register user...")

    # Enter user into database
    try:
        successfulRegister = __enter_db(reqPack.get_fields(0), reqPack.get_fields(1), reqPack.get_encrypted_fields(0))
    except IndexError:
        print("Error retrieving username, password, or public key from packet")
        return

    # Craft response packet
    if successfulRegister:
        # Log successful registration
        print("Registration successful as {user}".format(user=reqPack.get_fields(0)))

        # Craft success packet
        respPack = Packet("REGISTER", "DONE,OK")

        # Send success packet
        connection.sendall(respPack.send())

        return True
    else:
        # Log failed registration
        print("Client failed to register as {user}".format(user=reqPack.get_fields(0)))

        # Craft error packet
        respPack = Packet("REGISTER", "DONE,ERR")

        # Send error packet
        connection.sendall(respPack.send())

        return False


def __enter_db(user: str, pwd: str, pKey: bytes):
    # Check if user exists in database
    userExists = db.get_valid_user(user)

    # Check if user already exists
    if userExists:
        return False

    # Check username and password follow length rules
    if len(user) > 20 or len(user) < 1:
        print("Invalid username length")
        return False
    if len(pwd) > 1024 or len(pwd) < 10:
        print("Invalid password length")
        return False

    # Create user entry
    successfulProfileCreation = db.create_user(user, pwd)

    # Check profile creation was successful
    if not successfulProfileCreation:
        return False

    # Save user's public key
    pKey = pKey
    successfulKeyUpdate = db.update_key(user, pKey)

    return successfulKeyUpdate
