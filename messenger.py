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

    """def decryptReport(self, ct):
        pt = dec_elgamal(ct)
        return pt"""

    def signCert(self, cert):
        signature = self.server_signing_key.sign(cert, ec.ECDSA(hashes.SHA256()))
        return signature

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):  #only need to remember the most recent chain key
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}
        self.private_k = ""
        self.public_k = ""

    def generateCertificate(self):
        self.private_k = ec.generate_private_key(ec.SECP256R1())
        self.public_k = self.private_k.public_key()
        return self.public_k.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) + self.name.encode('utf-8')

    def receiveCertificate(self, certificate, signature):
        self.server_signing_pk.verify(signature, certificate, ec.ECDSA(hashes.SHA256()))
        tempname = certificate[178:].decode('utf-8')
        self.certs[tempname] = certificate

        self.conns[tempname] = {
            0: None,   # Placeholder for public key
            1: None,   # Placeholder for root key
            2: None,   # Placeholder for sending key
            3: None,   # Placeholder for receiving key
            4: False  # Placeholder for sender status
        }

        self.conns[tempname][0] = load_pem_public_key(certificate[:178], 'default_backend()') #first index under received client's name in working client conns is public key
        ##print(load_pem_public_key(certificate[:178], 'default_backend()'))
        helper = self.private_k.exchange(ec.ECDH(), load_pem_public_key(certificate[:178], 'default_backend()'))
        self.conns[tempname][1] = helper #second index under received client's name in working client conns is root key, initted as DH shared secret
        self.conns[tempname][2] = "" #sending key init
        self.conns[tempname][3] = "" #receiving key init
            
        

    def sendMessage(self, name, message):
        """try:"""
        #check to see if a message has been sent or received yet, if no use DH handshake from certs, if yes use new DH handshake
        if len(self.conns[name][2]) == 0 and len(self.conns[name][3]) == 0:
            k1 = self.symm_rat(self.conns[name][1], self.conns[name][1]) #k1 is gonna be output of root kdf

            send_ck = k1[32:] #extract last 32 for send chain key construction
            root_k = k1[:32] #extract first 32 for root key
            self.conns[name][1] = root_k

            k2 = self.symm_rat(send_ck, bytearray(16)) #k2 is gonna be output of send chain kdf
            send_ck = k2[:32] #extract first 32 for storing send key
            message_k = k2[32:] #extract last 32 for message key and encryption
            self.conns[name][2] = send_ck

        else:
            if not self.conns[name][4]:
                self.private_k = ec.generate_private_key(ec.SECP256R1())
                self.public_k = self.private_k.public_key()
                #generate new key pair


                new_DH= self.private_k.exchange(self.conns[name][0])
                #new DH shared secret
                k1 = self.symm_rat(self.conns[name][1], new_DH) #k1 is gonna be output of root kdf

                send_ck = k1[32:] #extract last 32 for send chain key construction
                root_k = k1[:32] #extract first 32 for root key
                self.conns[name][1] = root_k

                k2 = self.symm_rat(send_ck, 4) #k2 is gonna be output of send chain kdf
                send_ck = k2[:32] #extract first 32 for storing send key
                message_k = k2[32:] #extract last 32 for message key and encryption
                self.conns[name][2] = send_ck
            else:
                k2 = self.symm_rat(self.conns[name][2], bytearray(16)) #k2 is gonna be output of send chain kdf
                send_ck = k2[:32] #extract first 32 for storing send key
                message_k = k2[32:] #extract last 32 for message key and encryption
                self.conns[name][2] = send_ck

        aesgcm = AESGCM(message_k)
        nonce = bytearray(16)
        
        ct = aesgcm.encrypt(nonce, message.encode('utf-8'), None)

        self.conns[name][4] = True #maintains clients position as sender, if this is true and send message called again no need for new keys

        return self.public_k, ct
        """
        except Exception as e:
            print(f"Encryption Failed")
            raise(e)
        """

    def receiveMessage(self, name, header, ciphertext):
        try:
            if len(self.conns[name][2]) == 0 and len(self.conns[name][3]) == 0:
                k1 = self.symm_rat(self.conns[name][1], self.conns[name][1]) #k1 is gonna be output of root kdf
                
                receive_ck = k1[32:] #extract last 32 for receive chain key construction
                root_k = k1[:32] #extract first 32 for root key
                self.conns[name][1] = root_k

                k2 = self.symm_rat(receive_ck, bytearray(16)) #k2 is gonna be output of send chain kdf
                receive_ck = k2[:32] #extract first 32 for storing send key
                message_k = k2[32:] #extract last 32 for message key and encryption
                self.conns[name][3] = receive_ck
            else:
                self.conns[name][0] = header
                new_DH= self.private_k.exchange(self.conns[name][0])
                #new DH shared secret
                k1 = self.symm_rat(self.conns[name][1], new_DH) #k1 is gonna be output of root kdf

                receive_ck = k1[32:] #extract last 32 for receive chain key construction
                root_k = k1[:32] #extract first 32 for root key
                self.conns[name][1] = root_k

                k2 = self.symm_rat(send_ck, bytearray(16)) #k2 is gonna be output of send chain kdf
                send_ck = k2[:32] #extract first 32 for storing send key
                message_k = k2[32:] #extract last 32 for message key and encryption
                self.conns[name][2] = send_ck

            aesgcm = AESGCM(message_k)
            nonce = bytearray(16)
            pt = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

            self.conns[name][4] = False #identifies client as receiver of last message, to decide if new DH pair needed for send 

            return pt
        except Exception as e:
            print(f"Decryption Failed")
            raise(e)
        

    """def report(self, name, message):
        ct = self.enc_elgamal(name, message) 
        return ct"""
    
    """def enc_elgamal(self, name, message): #how to include name? A: as a tuple, pickle ####change to hashed elgamal
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
        
        return pt"""
    
    def symm_rat(self, root_key, constant):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            info=root_key,
            salt=None
        )
        chain_key = hkdf.derive(constant)
        return chain_key