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


def encrypt_file(key, filename, pchunksize):
    chunksize = pchunksize*1024
    outputFileName = "(encypt)"+filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)

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


def getSecretKey(password):
    hashKey = SHA256.new(password.encode('utf-8'))
    return hashKey.digest()


def Main():
    # filename=input("file:  ")
    # password = input("password  :")
    encrypt_file(getSecretKey('abcd'), 'sample.txt', 1024)
    print("DONE ")


if __name__ == '__main__':
    Main()
