import os
import pickle
import string

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
        shared_k = self.private_k.exchange(load_pem_public_key(self.certs[name][:178], 'default_backend()'))
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            info=shared_k,
        )
        key = hkdf.derive()

        return

    def receiveMessage(self, name, header, ciphertext):
        raise Exception("not implemented!")
        return

    def report(self, name, message):
        ct = self.enc_elgamal(name, message) 
        return ct
    
    def enc_elgamal(self, name, message): #how to include name? A: as a tuple, pickle ####change to hashed elgamal
        pk = serialization.load_pem_public_key(server_encryption_pk) #serialize key here
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
