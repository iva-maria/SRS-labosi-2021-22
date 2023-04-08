import sys
from base64 import b64encode
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from getpass import getpass

def save_login_info(users, username, salt, tag):
    users.write(username)
    users.write(" ")
    users.write(b64encode(salt).decode("utf-8"))
    users.write(" ")
    users.write(b64encode(tag).decode("utf-8"))
    users.write("\n")

args = sys.argv

if(args[1] == 'add'):
    password = getpass("Password: ")
    passwordRepeat = getpass("Repeat password: ")

    if(password != passwordRepeat
        or len(password) < 8
        or not any(x.isdigit() for x in password)
        or not any(x.isalpha() for x in password)):
        print("User add failed. Password mismatch or illegal password format (password" +
            " must be at least 8 characters long and contain both letters and digits).")
    else:
        salt = get_random_bytes(32)
        key = scrypt(password, salt, 32, N = 2 ** 14, r = 8, p = 1, num_keys = 1)
        hmac = HMAC.new(key, digestmod = SHA256)
        tag = hmac.digest()

        users = open("users.txt", "a")
        save_login_info(users, args[2], salt, tag)
        users.close()

        print("User add successfully added.")
elif(args[1] == "passwd"):
    password = getpass("Password: ")
    passwordRepeat = getpass("Repeat password: ")

    if(password != passwordRepeat):
        print("Password change failed. Password mismatch.")
    else:
        users = open("users.txt", "r")
        userInfo = users.readlines()
        users.close()

        users = open("users.txt", "w")
        for user in userInfo:
            user = user.split(" ")
            if(user[0] == args[2]):
                salt = get_random_bytes(32)
                key = scrypt(password, salt, 32, N = 2 ** 14, r = 8, p = 1)
                hmac = HMAC.new(key, digestmod = SHA256)
                tag = hmac.digest()

                save_login_info(users, args[2], salt, tag)
            else:
                user = (" ").join(user)
                users.write(user)
        users.close()
        print("Password change successful.")
elif(args[1] == "forcepass"):
    users = open("users.txt", "r")
    userInfo = users.readlines()
    users.close()

    users = open("users.txt", "w")
    for user in userInfo:
        user = user.split(" ")
        if(user[0] == args[2]):
            user = ("FORCEPASS").join(user)
        else:
            user = (" "). join(user)
        users.write(user)
    users.close()
    print("User will be requested to change password on next login.")
elif(args[1] == "del"):
    users = open("users.txt", "r")
    userInfo = users.readlines()
    users.close()

    users = open("users.txt", "w")
    for user in userInfo:
        user = user.split(" ")
        if(user[0] != args[2]):
            user = (" ").join(user)
            users.write(user)
    users.close()
    print("User successfully removed.")