#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 11 11:44:13 2023

@author: kaushikkumartrs
"""


import time
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512, SHA3_256
from Crypto.PublicKey import RSA
from Crypto.Signature import DSS
from Crypto.PublicKey import DSA
from Crypto.Util.Padding import pad, unpad
import os


def write_to_csv(data,algorithm,file_size_type):

    file_name = str("decrypted_results/"+algorithm+'_'+file_size_type+".txt")
    file = open(file_name, "wb")      
    file.write(data)
    file.close
    
def print_results(encryption_time, decryption_time, enc_speed_per_byte,dec_speed_per_byte):
    
    print("Encryption time",float(encryption_time * 1e3))
    print("Decryption time",float(decryption_time * 1e3))
    
    print("Encryption Speed per byte",float(enc_speed_per_byte * 1e3))
    print("Decryption Speed per byte",float(dec_speed_per_byte * 1e3))
    
    print("--------------------------------------------------")
    
    
#AES CBC Mode Encryption and Decryption
def AES_encryption_cbc(data,byte,file_size_type,aes_key):

        
    start_time = time.time()
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_text = cipher.encrypt(pad(data, AES.block_size))
    encryption_time = time.time() - start_time

    start_time = time.time()
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_text), AES.block_size)
    decryption_time = time.time() - start_time

    enc_speed_per_byte = encryption_time/len(data)
    dec_speed_per_byte = decryption_time/len(data)
    
    
    print_results(encryption_time,decryption_time,
                  enc_speed_per_byte,dec_speed_per_byte)
    write_to_csv(decrypted_data, "AES_"+str(byte)+"_CBC", file_size_type)


#AES CTR Mode Encryption and Decryption
def AES_encryption_ctr(data,byte,file_size_type,aes_key):

    start_time = time.time()
    iv = os.urandom(8)
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce = iv)
    encrypted_text = cipher.encrypt(pad(data, AES.block_size))
    encryption_time = time.time() - start_time
    
    start_time = time.time()
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce = iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_text), AES.block_size)
    decryption_time = time.time() - start_time
    
    enc_speed_per_byte = encryption_time/len(data)
    dec_speed_per_byte = decryption_time/len(data)
    
    print_results(encryption_time,decryption_time, 
                  enc_speed_per_byte,dec_speed_per_byte)
    write_to_csv(decrypted_data, "AES_"+str(byte)+"_CTR", file_size_type)



#RSA Encryption and Decryption
def RSA_encryption(data,bits,file_size_type,rsa_key):
    
    #maximum size rsa can encrypt is the key size
    chunk_len = int(bits/8)-42
    encrypted_chunks = []
    decrypted_chunks = []

    #Encryption
    start_time = time.time()
    for i in range(0, len(data), chunk_len):
        chunk = data[i:i+chunk_len]
        cipher = PKCS1_OAEP.new(rsa_key.publickey())
        encrypted_chunks.append(cipher.encrypt(chunk))
    encryption_time = time.time() - start_time
    
    #Decryption
    #f = open('myrsakey.pem','r')
    #priv_key = RSA.import_key(f.read())
    priv_key = RSA.import_key(rsa_key.export_key('PEM'))
    start_time = time.time()
    for chunk in encrypted_chunks:
        cipher = PKCS1_OAEP.new(priv_key)
        decrypted_chunks.append(cipher.decrypt(chunk))
    decryption_time = time.time() - start_time
    
    enc_speed_per_byte = encryption_time/len(data)
    dec_speed_per_byte = decryption_time/len(data)
    
    print_results(encryption_time, decryption_time, 
                  enc_speed_per_byte,dec_speed_per_byte)

    write_to_csv(b" ".join(decrypted_chunks), "RSA_"+str(bits), file_size_type)



#Hash Functions
def sha_hash_function(data,bytes_,sha3,):
    start_time = time.time()
    
    if bytes_ == 256 and sha3 == False:
        hash_value = SHA256.new(data).hexdigest()
        hashing_time = time.time() - start_time
        print("SHA256 Hash:",hash_value)
        print("Hashing Time",float(hashing_time * 1e3))
        
        
    elif bytes_ == 512 and sha3 == False:
        hash_value = SHA512.new(data).hexdigest()
        hashing_time = time.time() - start_time
        print("SHA512 Hash:",hash_value)
        print("Hashing Time",float(hashing_time * 1e3))
        
        
    elif bytes_ == 256 and sha3 == True:
        hash_value = SHA3_256.new(data).hexdigest()
        hashing_time = time.time() - start_time
        print("SHA3 256 Hash:",hash_value)
        print("Hashing Time",float(hashing_time * 1e3))
    
    print("Hashing Speed per byte",float((hashing_time/len(data)) * 1e3))
    print("--------------------------------------------------")
    
    
    
#Digital Signature
def DSS_(data,bits,dss_key):

    #print("Key Generation time",key_generation_time * 1e3)
    
    signer = DSS.new(dss_key, 'fips-186-3')
    start_time = time.time()
    signature = signer.sign(SHA256.new(data))
    signing_time = time.time() - start_time
    
    print("Signing time",float(signing_time * 1e3))
    print("Signing speed per byte",float((signing_time/len(data)) * 1e3))
    
    pub_key = DSA.import_key(dss_key.publickey().export_key())
    verifier = DSS.new(pub_key, 'fips-186-3')
    
    try:
        start_time = time.time()
        verifier.verify(SHA256.new(data), signature)
        verification_time = time.time() - start_time
        print("Verification time",float(verification_time * 1e3))
        print("Verification speed per byte",float((verification_time/len(data)) * 1e3))
        
        print("The message is authentic")
    except ValueError:
        print("The message is not authentic")
    
    print("--------------------------------------------------")
    

def generate_key():
    
    os.urandom(16)
    
    key_dict = {}
    
    start_time = time.time()
    key_dict["aes_key_128"] = os.urandom(16)
    print("AES 128 bit Key Generation Time", (time.time() - start_time) * 1e3)
    
    start_time = time.time()
    key_dict["aes_key_256"] = os.urandom(32)
    print("AES 256 bit Key Generation Time", (time.time() - start_time) * 1e3)
    
    start_time = time.time()
    key_dict["rsa_key_2048"] = RSA.generate(2048)
    print("RSA 2048 bit Key Generation Time", (time.time() - start_time) * 1e3)
    
    start_time = time.time()
    key_dict["rsa_key_3072"] = RSA.generate(3072)
    print("RSA 3072 bit Key Generation Time", (time.time() - start_time) * 1e3)
    
    start_time = time.time()
    key_dict["dss_key_2048"] = DSA.generate(2048)
    print("DSS 2048 bit Key Generation Time", (time.time() - start_time) * 1e3)
    
    start_time = time.time()
    key_dict["dss_key_3072"] = DSA.generate(3072)
    print("DSS 3072 bit Key Generation Time", (time.time() - start_time) * 1e3)
    
    return key_dict
        
        

def trigger_functions(data,file_size_type,keys):
    
    
    print("AES Ecryption CBC")
    AES_encryption_cbc(data,16,file_size_type,keys["aes_key_128"])
    
    print("AES Ecryption CTR - 128 bits")
    AES_encryption_ctr(data,16,file_size_type,keys["aes_key_128"])
    
    print("AES Ecryption CTR - 256 bits") 
    AES_encryption_ctr(data,32,file_size_type,keys["aes_key_256"])
    
    if file_size_type == '1KB':
        print("RSA encryption with 2048 bits")
        RSA_encryption(data, 2048,file_size_type,keys["rsa_key_2048"])
        
    if file_size_type == '1KB':
        print("RSA encryption with 3072 bits")
        RSA_encryption(data, 3072,file_size_type,keys["rsa_key_3072"])
    
    sha_hash_function(data,256, False)
    sha_hash_function(data,512, False)
    sha_hash_function(data,256, True)

    print("Digital Signature - 2048 bit key")
    DSS_(data, 2048,keys["dss_key_2048"])
    print("Digital Signature - 3072 bit key")
    DSS_(data, 3072,keys["dss_key_3072"])
    
    
    
if __name__ == "__main__":
    
    current_directory = os.getcwd()
    final_directory = os.path.join(current_directory, r'decrypted_results')
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)
    
    small_data = open("small_file.txt", 'rb').read()
    large_data = open("large_file.txt", 'rb').read()
    RSA_1MB_data = open("RSA_1MB_File.txt",'rb').read()
    
    keys = generate_key()
    
    print("--------------Processing 1KB Data---------------------")
    trigger_functions(small_data,"1KB",keys)
    
    print("--------------Processing 1MB Data for RSA-------------")
    print("RSA encryption with 2048 bits")
    RSA_encryption(RSA_1MB_data,2048,"1MB",keys["rsa_key_2048"])
    
    print("RSA encryption with 3072 bits")
    RSA_encryption(RSA_1MB_data,3072,"1MB",keys["rsa_key_3072"])
    
    print("--------------------------------------------------")
    print("-------------Processing 10MB Data--------------------")
    trigger_functions(large_data,"10MB",keys)
    
    print("Pipeline Finished successfully")




