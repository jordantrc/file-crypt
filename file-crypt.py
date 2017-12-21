#
# Encrypts/decrypts files using AES 256
#
#


import getpass
import hashlib
import math
import os
import struct
import sys
import time
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import random

class Logger:

    def __init__(self):
        """constructor"""
        self.log_enabled = False

    def __init__(self, l):
        """constructor"""
        self.log_enabled = l

    def log(self, message):
        """logs message if log is true"""
        if self.log_enabled:
            print(message)


class Cryptor:
    
    def __init__(self, p, iv=None):
        """constructor with values"""
        self.pbkdf_rounds = 138514  # generated from random.randint(100000,150000)
        self.salt= b'1px89h3rS6ehkfaRarhohYwIQTn6H06VUZNwTYEBQsCNgsLM'
        self.chunksize = 64 * 1024

        if iv is None:
            self.generate_iv()
        else:
            self.initialization_vector = iv

        #print("length of IV = %s" % (len(self.initialization_vector)) )
        self.password = bytes(p, 'ascii')
        # generate the key from the password and salt
        # for this purpose, the hashlib
        # password based key derivation function
        # is used
        self.key = hashlib.pbkdf2_hmac('sha256', self.password, self.salt, self.pbkdf_rounds)

        self.cryptor = AES.new(self.key, AES.MODE_CBC, self.initialization_vector)


    def __repr__(self):
        """returns a string representing the object"""
        string = "key = " + str(self.key) + "\n"
        string += "password = " + str(self.password) + "\n"
        string += "salt = " + str(self.salt) + "\n"
        string += "initialization vector = " + str(self.initialization_vector) + "\n"

        return string


    def read_iv(file):
        """reads the original size and initialization vector from an encrypted file"""
        with open(file, 'rb') as infile:
            size = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)

        return iv


    def generate_iv(self):
        """creates a new random initialization vector, used for 
        encryption only"""
        self.initialization_vector = b''
        for i in range(16):
            self.initialization_vector += bytes([random.randint(0,255)])


    def encrypt_file(self, file):
        """encrypts a given file, returns the number of bytes written
        to the file"""
        out_filename = file + ".enc"
        filesize = os.path.getsize(file)
        bytes_written = 0
        source_sha1 = hashlib.sha1()

        with open(file, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(self.initialization_vector)

                while True:
                    chunk = infile.read(self.chunksize)
                    source_sha1.update(chunk)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        # pad the chunk
                        chunk += b' ' * (16 - len(chunk) % 16)

                    outfile.write(self.cryptor.encrypt(chunk))
                    bytes_written += len(chunk)

        return source_sha1


    def decrypt_file(self, file):
        """decrypts the provided file"""
        out_filename = os.path.splitext(file)[0]
        dest_sha1 = hashlib.sha1()

        with open(file, 'rb') as infile:
            size = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            with open(out_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(self.chunksize)
                    #print("chunk length = %s" % (len(chunk)))
                    if len(chunk) == 0:
                        break
                    outfile.write(self.cryptor.decrypt(chunk))
                outfile.truncate(size)

        # since the output file is truncated after writing, need to re-read to get hash
        with open(out_filename, 'rb') as infile:
            while True:
                chunk = infile.read(self.chunksize)
                dest_sha1.update(chunk)
                if len(chunk) == 0:
                    break

        return dest_sha1


def main():
    """encrypts and decrypts files"""
    log = Logger(False)

    if len(sys.argv) < 3:
        print("Not enough arguments, exiting")
        print("Usage: file-crypt.py [encrypt|decrypt] filename")
        sys.exit(1)
    else:
        action = sys.argv[1]
        file = sys.argv[2]

    # prompt for password
    password = getpass.getpass()
    password_confirm = getpass.getpass("Confirm Password: ")
    if password != password_confirm:
        print("Passwords do not match")
        sys.exit(1)

    log.log("Got password %s" % (password))
    log.log("Action is %s" % (action))
    
    if action == "encrypt":
        # create cryptor object
        cryptor = Cryptor(password)
        log.log("Created cryptor object:")
        log.log(str(cryptor))
        
        start_time = time.time()
        file_hash = cryptor.encrypt_file(file)
        end_time = time.time()
        print("File successfully encrypted in %s seconds" % (end_time - start_time))
        print("Source file SHA1 hash = %s" % (file_hash.hexdigest()))
    
    elif action == "decrypt":
        # read the size and initialization vector from the source file
        iv = Cryptor.read_iv(file)
        # create cryptor object
        cryptor = Cryptor(password, iv=iv)
        
        start_time = time.time()
        file_hash = cryptor.decrypt_file(file)
        end_time = time.time()
        print("File successfully decrypted in %s seconds" % (end_time - start_time))
        print("Decrypted file SHA1 hash = %s" % (file_hash.hexdigest()))
    
    else:
        print("No valid action specified, exiting")
        sys.exit(1)


if __name__ == "__main__":
    main()
