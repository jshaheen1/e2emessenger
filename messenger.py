import os
import pickle
import string
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MessengerServer:                                          
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key                              
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        pt = dec_elgamal(ct)
        return pt

    def signCert(self, cert):
        signature = self.server_signing_key.sign(cert, ec.ECDSA(hashes.SHA256()))
        return signature

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):  #only need to remember the most recent chain key
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {} # store DH keys per convo here
        self.certs = {}
        self.private_k = ""
        self.public_k = ""
        #self.

    def generateCertificate(self):
        self.private_k = ec.generate_private_key(ec.SECP256R1())
        self.public_k = self.private_k.public_key()
        return self.public_k.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) + self.name.encode('utf-8')

    def receiveCertificate(self, certificate, signature):
        try:
            self.server_signing_pk.verify(signature, certificate, ec.ECDSA(hashes.SHA256()))
            self.certs[certificate[178:].decode('utf-8')] = certificate
        except Exception as e:
            print(f"An exception of type {type(e).__name__} occurred: {e}")
            raise(e)
            
        

    def sendMessage(self, name, message):
        try:
            shared_k = self.private_k.exchange(load_pem_public_key(self.certs[name][:178], 'default_backend()')) ## move this to cert
            shared_k = 
            k = self.symm_rat(self.server_encryption_pk, shared_k)
            self.cert[name,] = k[:255]   
            message_k = k[256:] # confirm in OH abt key length and gen

            aesgcm = AESGCM(message_k)
            nonce = bytearray(16)
            
            ct = aesgcm.encrypt(nonce, message)
            return nonce, ct
        except Exception as e:
            print(f"Encryption Failed")
            raise(e)

    def receiveMessage(self, name, header, ciphertext):
        try:
            shared_k = self.private_k.exchange(load_pem_public_key(self.certs[name][:178], 'default_backend()'))
        
            chain_k, message_k =  self.symm_rat(self.server_encryption_pk, shared_k)    # confirm in OH abt key length and gen

            aesgcm = AESGCM(message_k)
            nonce = bytearray(16)
            pt = aesgcm.decrypt(nonce, ciphertext)
            return pt
        except Exception as e:
            print(f"Decryption Failed")
            raise(e)
        

    def report(self, name, message):
        ct = self.enc_elgamal(name, message) 
        return ct
    
    def enc_elgamal(self, name, message): #how to include name? A: as a tuple, pickle ####change to hashed elgamal
        pk = serialization.load_pem_public_key(self.server_encryption_pk) #serialize key here
        print(pk)   #check
        for i in range(0,len(message)):
            ct[i]= pk*ord(ct[i])
        digest = hashes.Hash(hashes.SHA256())
        digest.update(ct)
        k = digest.finalize()
        ##AESGCM
        return ct, tag

    def dec_elgamal(self, ciphertext): ##use 
        sk = serialization.load_pem_private_key(server_decryption_key) #deserialize key here
        print(sk)   #check
        ##add verify part
        for i in range(0,len(ciphertext)):
            pt.append(chr(int(ciphertext[i]/sk)))
        
        return pt
    
    def symm_rat(self, root_key, constant):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            info=root_key,
            salt=None
        )
        chain_key = hkdf.derive(constant)
        message_key = hkdf.derive(chain_key) ##????????? is this the right way????????? other options: truncating the key in half, sha-256 the key??
        return chain_key, message_key

class Certificate:
    def __init__(self, ecpk, name):
        self.ecpk = ecpk
        self.name = name
        