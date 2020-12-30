# Custom imports
import src.db as db
from src.packet import Packet

def register(connection, reqPack):
    # Request packet structure:
    # <username>,<password>,<public key>
    print("Attempting to register user...")

    # Enter user into database
    successfulRegister = __enter_db(reqPack.get_fields(0), reqPack.get_fields(1), reqPack.get_fields(2))

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

    # Create user entry
    successfulProfileCreation = db.create_user(user, pwd)

    # Check profile creation was successful
    if not successfulProfileCreation:
        return False

    # Save user's public key
    pKey = pKey.encode('utf-8')
    successfulKeyUpdate = db.update_key(user, pKey)

    return successfulKeyUpdate
