"""Registers the user with the database

        Returns:
            True if successful, False if unsuccessful
"""
import db

def register(connection, user, pwd, pKey):
    # Create user entry in database
    if not __create_user(user, pwd):
        print("User entry failed: %s" % user)
        return False

    print("Entry created for {user}".format(user=user))

    return __save_user_key(user, pKey)

def __create_user(user, pwd):
    # Check if user already exists
    if db.get_valid_user(user):
        return False
    else:
        return db.create_user(user, pwd)

def __save_user_key(user, pKey):
    pKey = pKey.encode('utf-8')
    
    return db.update_key(user, pKey)