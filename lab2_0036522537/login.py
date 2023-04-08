from hashlib import sha256
import sys
from base64 import b64encode, b64decode
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

users = open("users.txt", "r")
userInfo = users.readlines()
users.close()

existingUser = False
forcePass = False

users = open("users.txt", "w")
for user in userInfo:
    if("FORCEPASS" in user):
        forcePass = True
        user = user.split("FORCEPASS")
    else:
        user = user.split(" ")

    if(user[0] == args[1]):
        existingUser = True
        password = getpass("Password: ")

        if(forcePass == True):
            key = scrypt(password, b64decode(user[1]), 32, N = 2 ** 14, r = 8, p = 1)
            oldTag = b64decode(user[2])
            newHmac = HMAC.new(key, digestmod = SHA256)
            newTag = newHmac.digest()

            if(oldTag == newTag):
                newPassword = getpass("New password: ")
                newPasswordRepeat = getpass("Repeat new password: ")
                if(newPasswordRepeat == newPassword
                    and newPassword != password
                    and len(newPassword) >= 8
                    and any(x.isdigit() for x in password)
                    and any(x.isalpha() for x in password)):
                    salt = get_random_bytes(32)
                    key = scrypt(password, salt, 32, N = 2 ** 14, r = 8, p = 1)  #password?
                    hmacNewPass = HMAC.new(key, digestmod = SHA256)
                    tagNewPass = hmacNewPass.digest()

                    save_login_info(users, user[0], salt, tagNewPass)
                    print("Login successful.")
                else:
                    print("Login failed. Password mismatch or illegal password format (password" +
                        " must be at least 8 characters long and contain both letters and digits).")
                    users.write(("FORCEPASS").join(user))
            else:
                print("Login failed. Username or password incorrect.")
                users.write(("FORCEPASS").join(user))
        else:
            key = scrypt(password, b64decode(user[1]), 32, N = 2 ** 14, r = 8, p = 1)
            oldTag = b64decode(user[2])
            newHmac = HMAC.new(key, digestmod = SHA256)
            newTag = newHmac.digest()

            user = (" ").join(user)
            users.write(user)

            if(oldTag == newTag):
                print("Login successful.")
            else:
                print("Login failed. Username or password incorrect.")
    else:
        user = (" ").join(user)
        users.write(user)
users.close()

if(existingUser == False):
    print("Login failed. Username or password incorrect.")