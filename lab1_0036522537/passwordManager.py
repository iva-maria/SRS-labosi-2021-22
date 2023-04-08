from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import sys
from termcolor import colored

def write_in_info(iv, salt, tag):
    file = open("info.txt", "w")
    file.write(iv)
    file.write(",")
    file.write(b64encode(salt).decode("utf-8"))
    file.write(",")
    file.write(b64encode(tag).decode("utf-8"))
    file.close()

def write_in_passwords(text):
    file = open("passwords.txt", "w")
    file.write(text)
    file.close()

args = sys.argv

if args[1] == 'init':
    masterPassword = args[2]

    salt = get_random_bytes(16)
    key = scrypt(masterPassword, salt, 16, N = 2 ** 14, r = 8, p = 1, num_keys = 2)
    cipher = AES.new(key[0], AES.MODE_CBC)

    data = "test"
    ctBytes = cipher.encrypt(pad(data.encode("utf-8"), AES.block_size))
    iv = b64encode(cipher.iv).decode("utf-8")

    cipherText = b64encode(ctBytes).decode("utf-8")
    write_in_passwords(cipherText)

    hmac = HMAC.new(key[1], msg = cipherText.encode("utf-8"), digestmod = SHA256)
    tag = hmac.digest()

    write_in_info(iv, salt, tag)

    print("Password manager initialized.")

elif args[1] == 'put':
    existingAddress = False
    oldAddressAndPassword = ""
    newAddressAndPassword = ""
    
    file = open("info.txt", "r")
    info = file.read().split(",")
    iv = b64decode(info[0])
    salt = b64decode(info[1])
    tag = b64decode(info[2])
    file.close()

    masterPassword = args[2]

    file = open("passwords.txt", "r")
    passwords = file.read()
    file.close()

    key = scrypt(masterPassword, salt, 16, N = 2 ** 14, r = 8, p = 1, num_keys = 2)

    if tag == HMAC.new(key[1], msg = passwords.encode("utf-8"), digestmod=SHA256).digest():
        cipher = AES.new(key[0], AES.MODE_CBC, iv = iv)
        data = unpad(cipher.decrypt(b64decode(passwords)), AES.block_size).decode("utf-8") + "\n"

        for pair in data.split("\n"):
            oldAddressAndPassword = pair
            pair = pair.split(':')
            if pair[0] == args[3]:
                pair[1] = args[4]
                newAddressAndPassword = pair[0] + ":" + pair[1]
                existingAddress = True
                break

        if(existingAddress == True):
            data = data.replace(oldAddressAndPassword, newAddressAndPassword)
        else:
            data += args[3] + ':' + args[4] + "\n"

        salt = get_random_bytes(16)
        key = scrypt(masterPassword, salt, 16, N=2**14, r=8, p=1, num_keys=2)

        cipher = AES.new(key[0], AES.MODE_CBC)
        ctBytes = cipher.encrypt(pad(data.encode("utf-8"), AES.block_size))
        iv = b64encode(cipher.iv).decode("utf-8")

        cipherText = b64encode(ctBytes).decode("utf-8")
        write_in_passwords(cipherText)

        hmac = HMAC.new(key[1], msg = cipherText.encode("utf-8"), digestmod = SHA256)
        tag = hmac.digest()

        write_in_info(iv, salt, tag)

        print(f"Stored password for {args[3]}.")

    else:
        print("Master password incorrect or integrity check failed.")

elif args[1] == 'get':
    masterPassword = args[2]

    file = open("info.txt", "r")
    info = file.read().split(",")
    file.close()
    iv = b64decode(info[0])
    salt = b64decode(info[1])
    tag = b64decode(info[2])

    key = scrypt(masterPassword, salt, 16, N = 2 ** 14, r = 8, p = 1, num_keys = 2)

    file = open("passwords.txt", "r")
    passwords = file.read()
    file.close()

    if tag == HMAC.new(key[1], msg = passwords.encode("utf-8"), digestmod = SHA256).digest():
        cipher = AES.new(key[0], AES.MODE_CBC, iv = iv)
        data = unpad(cipher.decrypt(b64decode(passwords)), AES.block_size).decode("utf-8").split("\n")
        for pair in data:
            pair = pair.split(':')
            if pair[0] == args[3]:
                print(f"Password for {pair[0]} is: {pair[1]}.")
                break
    else:
        print("Master password incorrect or integrity check failed.")
