from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from hashlib import sha256
import os
from Crypto import Random
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA

#=============================/ Function /===============================

# create_RSA_keys  
# create RSA keys --> public and private
def create_RSA_keys(name_split):
    key = RSA.generate(2048)
    private_key = key.export_key()
    fo = open(name_split+"private.key", "wb")
    fo.write(private_key)
    fo.close()

    public_key = key.publickey().export_key()
    fo = open(name_split+"public.key", "wb")
    fo.write(public_key)
    fo.close()


# press '1'
def encrypt_text_file(key, file_name):
        
        chunksize = 64*1024
        outputFile = "(encrypt)."+file_name
        filesize = str(os.path.getsize(file_name)).zfill(16)
        IV = Random.new().read(16)
        name_split = file_name.split('.')

        encryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(file_name, 'rb') as infile:  
            with open(outputFile, 'wb') as outfile:  
                outfile.write(filesize.encode('utf-8'))
                outfile.write(IV)

                while True:
                    chunk = infile.read(chunksize)

                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' '*(16-(len(chunk) % 16))

                    outfile.write(encryptor.encrypt(chunk))
        if name_split[1] == 'txt':
            create_RSA_keys(name_split[0])
            Digital_signature(name_split[0])


# press '2'
def encrypt_file(key, file_name):
        
        chunksize = 64*1024
        outputFile = "(encrypt)."+file_name
        filesize = str(os.path.getsize(file_name)).zfill(16)
        IV = Random.new().read(16)
        name_split = file_name.split('.')

        encryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(file_name, 'rb') as infile:  
            with open(outputFile, 'wb') as outfile:  
                outfile.write(filesize.encode('utf-8'))
                outfile.write(IV)

                while True:
                    chunk = infile.read(chunksize)

                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' '*(16-(len(chunk) % 16))
                        
                    outfile.write(encryptor.encrypt(chunk))


# press '3'
def decrypt(key, file_name):
            chunksize = 64*1024
            outputFile = "de"+file_name[11:]
            name_split = file_name.split('.')

            if name_split[2] == 'txt':
                if not verify_keys(name_split[1]):
                    return False
                    
            with open(file_name, 'rb') as infile:
                filesize = int(infile.read(16))
                IV = infile.read(16)

                decryptor = AES.new(key, AES.MODE_CBC, IV)

                with open(outputFile, 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunksize)

                        if len(chunk) == 0:
                            break

                        outfile.write(decryptor.decrypt(chunk))

                    outfile.truncate(filesize)
            return True


# Digital_signature
def Digital_signature(name_split):
    #import codecs

    file_in = open("(encrypt)."+name_split+".txt", "rb")
    message = file_in.read()
    file_in.close()
    key = RSA.import_key(open(name_split+'private.key').read())
    h = SHA512.new(message)

    signer=pkcs1_15.new(key)
    signature=signer.sign(h)
    
    fo = open(name_split+"signature.pem", "wb")
    fo.write(signature)
    fo.close()

    fo = open(name_split+"message.txt", "wb")
    fo.write(message)
    fo.close()


# hash_message
def hash_message(message):
    hash = SHA512.new(message)
    return hash


# verify_message
def verify_keys(name_split):
    key = RSA.import_key(open(name_split+'public.key').read())
    file_in = open(name_split+"message.txt", "rb")
    message=file_in.read()
    file_in.close()

    file_in = open(name_split+"signature.pem", "rb")
    signature=file_in.read()
    file_in.close()

    try:
        pkcs1_15.new(key).verify(hash_message(message), signature)
        print ("The signature is valid.")
        return True
    except (ValueError, TypeError):
        print ("The signature is not valid.")
        return False

# -------------------------/ Radom AES key /-------------------------------
# create AES key in folder AES
def createAES():
    # key AES 256 bits
    key = get_random_bytes(32)
    # save AES key
    fileAES = "AES/(enc).aes.txt"
    with open(fileAES, 'wb') as f:
        f.write(key)
        f.close()
    print("create AES ")
    return key

# get AES for decrypt
def getAES():
    file_in = open("AES/(enc).aes.txt", "rb")
    key = file_in.read()
    file_in.close()
    print("get AES ")
    return key

#================================/ Main /==================================

def Main():
    while True:
        choice = int(input(
                '''Select Mode You Want to Encrypt & Decrypt :\n1. press '1' encrypt text file
                \n2. press '2' encrypt file (ex.picture)
                \n3. press '3' decrypt file
                \n4. press '4' exit 
                \nSelect Mode You Want : '''))
        
        if choice == 1:
            file_name = input("File to encrypt (.txt) : ")
            encrypt_text_file(createAES(),file_name)
            print('successfully.\n')
        
        elif choice == 2:
            file_name = input("File to decrypt (ex.picture pdf) : ")
            encrypt_file(createAES(),file_name)
            print('successfully.\n')
            
        elif choice == 3:
            file_name = input("File to decrypt: ")
            if not decrypt(getAES(),file_name):
                print("cant decrypt")
                break
            print('successfully.\n')
        elif choice == 4:
            exit()
        else:
            print("Please select a valid option!\n")    

Main()