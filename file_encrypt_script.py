# Author: Melan Rashitha Dias
# Contact: melan96@github.io

# import CORE Pycrypto module for AES encryptions
import os
# Import AES symmetric cipher - Maintained fixed data block chuncks 16K
from Crypto.Cipher import AES

# SHA256 Secure Hash Algorithm
from Crypto.Hash import SHA256

# Random file postfixes
from Crypto import Random
import logging

# Encryption of FILE (METHOD=AES MODE=CBC)


def encrypt_file(key, filename, pchunksize):

    logging.info("Encryption started")
    chunksize = pchunksize*1024
    outputFileName = "(encypt)"+filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)
    logging.info("Encryption definitions configured")

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFileName, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' '*(16-(len(chunk) % 16))

                    outfile.write(encryptor.encrypt(chunk))


# Decryption of FILE
def decrypt_file(key, filename, pchunksize):
    chunksize = 64*pchunksize
    outputfile = filename[11:]

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)
    decryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(outputfile, 'wb') as outfile:
        while True:
            chunk = infile.read(chunksize)

            if len(chunk) == 0:
                break

            outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)


def getSecretKey(password):
    hashKey = SHA256.new(password.encode('utf-8'))
    return hashKey.digest()


def getUserInputs():
    # Python dictionaries handlings
    user_seq = {'filename': '', 'password': ''}

    # assign values
    user_seq['filename'] = raw_input("file:  ")
    user_seq['password'] = raw_input("password  :")

    # return dictionaries
    return user_seq


def Main():
    choice = raw_input("Do you wish (E)ncrypt or (D)ecrypt ?")

    if (choice.upper() == 'D'):
        # Prop to Decrypt
        print("Preseed D >> Decryption Util")

        payload = getUserInputs()
        decrypt_file(getSecretKey(payload.get('password')),
                     payload.get('filename'), 1024)

    elif(choice.upper() == 'E'):
        # Prop to Encrypt
        print("Preseed E >> Encryption Util")
        payload = getUserInputs()
        encrypt_file(getSecretKey(payload.get('password')),
                     payload.get('filename'), 1024)
    else:
        print("Invalid Argument : return 0")


if __name__ == '__main__':
    Main()
