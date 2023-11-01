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
        raise Exception("not implemented!")
        return

    def signCert(self, cert):
        signature = self.server_signing_key.sign(cert, ec.ECDSA(hashes.SHA256()))
        return signature

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}
        self.private_k = ""
        self.public_k = ""
        self.

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
            shared_k = self.private_k.exchange(load_pem_public_key(self.certs[name][:178], 'default_backend()'))
        
            k = self.symm_rat(self.server_encryption_pk, shared_k) #what abt multiple messages in a row? how to save the chain key?
            chain_k = k[:255]   
            message_k = k[256:] # confirm in OH abt key length and gen

            aesgcm = AESGCM(message_k)
            nonce = os.urandom(16) # include in header?
            
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
            nonce = #seperate nonce and tag?
            pt = aesgcm.decrypt(nonce, ciphertext)
            return pt
        except Exception as e:
            print(f"Decryption Failed")
            raise(e)
        

    def report(self, name, message):
        raise Exception("not implemented!")
        return
    
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
    
