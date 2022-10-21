import argparse
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

class FCRYPT(object):

    buffer_size = 65536 #64kb

    def parseArgs(self):
        #Parse the command line arguments
        parser = argparse.ArgumentParser(description='Pretty Good Privacy Implementation')
        parser.add_argument('--encrypt', help='encrypt a file', nargs=3, metavar=('<receiver_public_key>', '<plaintext_file>', '<encrypted_file>'))
        parser.add_argument('--decrypt', help='decrypt a file', nargs=3, metavar=('<receiver_private_key>', '<encrypted_file>', '<decrypted_file>'))
        args = parser.parse_args()

        if (args.encrypt is None and args.decrypt is None):
            parser.error('at least one of --encrypt or --decrypt is required')

        if(args.encrypt):
            receiver_public_key = args.encrypt[0]
            plaintext_file = args.encrypt[1]
            encrypted_file = args.encrypt[2]
            self.encrypt(receiver_public_key, plaintext_file, encrypted_file)
        
        if(args.decrypt):
            receiver_private_key = args.decrypt[0]
            encrypted_file = args.decrypt[1]
            decrypted_file = args.decrypt[2]
            self.decrypt(receiver_private_key, encrypted_file, decrypted_file)

    def encrypt(self, receiver_public_key, plaintext_file, encrypted_file):
        # Open the input and output files
        input_file = open(plaintext_file, 'rb')
        output_file = open(encrypted_file, 'wb')

        receiver_public_key = RSA.import_key(open(receiver_public_key).read()) #Import the public key of the receiver
        session_key = get_random_bytes(16) #Generate a random session key

        encrypter = PKCS1_OAEP.new(receiver_public_key) #Initialize the encrypter object from the receiver public key 
        enc_session_key = encrypter.encrypt(session_key) #Encrypt the session key

        #Encrypt the data with the AES session key
        encrypter_aes = AES.new(session_key, AES.MODE_EAX) 
        encrypred_data, tag = encrypter_aes.encrypt_and_digest(input_file.read())

        #Write the encrypted data to the provided file
        [ output_file.write(x) for x in (enc_session_key, encrypter_aes.nonce, tag, encrypred_data) ]

        #Close the input and output files
        input_file.close()
        output_file.close()

        #Finally print the Encryption Successful message.
        print('Encryption Successful.')

    def decrypt(self, receiver_private_key, encrypted_file, decrypted_file):
        #Open the encrypted and decrypted files
        encrypted_file = open(encrypted_file, 'rb')
        decrypted_file = open(decrypted_file, 'wb')

        receiver_private_key = RSA.import_key(open(receiver_private_key).read()) #Import the private key of the receiver

        #Extract the encrypted session key, nonce, tag and the encrypted data from the encrypted file
        enc_session_key, nonce, tag, encrypred_data = \
        [ encrypted_file.read(x) for x in (receiver_private_key.size_in_bytes(), 16, 16, -1) ]

        decrypter = PKCS1_OAEP.new(receiver_private_key) #Initialize the decrypter object from the receiver private key 
        session_key = decrypter.decrypt(enc_session_key) #Decrypt the session key

        #Decrypt the data with the AES session key
        decrypter_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = decrypter_aes.decrypt_and_verify(encrypred_data, tag)

        #Write the decrypted data to the provided file
        decrypted_file.write(data)

        #Close the encrypted and decrypted files
        encrypted_file.close()
        decrypted_file.close()

        #Finally print the Decryption Successful message.
        print('Decryption Successful.')

#Main
FCRYPT().parseArgs()

