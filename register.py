"""Registers the user with the database

        Returns:
            True if successful, False if unsuccessful
"""
import db

def register(connection, user, pwd):
    # Create user entry in database
    if not __create_user(user, pwd):
        print("User entry failed: %s" % user)
        msg = "BAD USERNAME".encode('utf-8')
        connection.sendall(msg)
        return False
    
    # Entry was created successfully, request user's public key
    print("User entry created: %s" % user)
    msg = "REQ KEY".encode('utf-8')
    print("Requesting key")
    connection.sendall(msg)

    # Wait for user to send key
    createdKey = __save_user_key(user, connection)

    return createdKey

def __create_user(user, pwd):
    # Check if user already exists
    if db.get_valid_user(user):
        return False
    else:
        return db.create_user(user, pwd)

def __save_user_key(user, connection):
    pKey = ""
    # Receive initial data
    data = connection.recv(1024)
    pKey += data.decode('utf-8')

    # Continue receiving data
    while len(data) == 1024:
        data = connection.recv(1024)
        print("Receiving key...")
        print("Received %s" % data.decode('utf-8'))
        pKey += data.decode('utf-8')

    print("Done receiving key")

    pKey = pKey.encode('utf-8')
    
    return db.update_key(user, pKey)