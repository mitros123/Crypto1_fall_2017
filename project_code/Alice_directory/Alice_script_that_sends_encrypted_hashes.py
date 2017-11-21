#!/usr/bin/env python3

#uses Elgamal from https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.ElGamal-module.html

import os
from pathlib import Path
import sys
from subprocess import Popen, PIPE
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import GCD
from Crypto.Cipher import AES
from Crypto.Hash import HMAC,SHA256
import time
import base64
import pickle

sys.path.append('../.') #add the parent directory into the path, so that we can import the custom crypto functions
from symmetric_crypto_functions import Symmetric_Crypto_Functions as SC


def find_hashes_names_indexes_of_our_files():
    global hashes
    global names
    global indexes

    process=Popen(["../find_hash_for_every_file.sh", we_are+'_files/'], stdout=PIPE,stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout_str=stdout.decode('ascii').split('\n')
    stdout_str = list(filter(None, stdout_str)) #Remove empty strings from list
    for line in stdout_str:
        hashes.append(line.split('-')[0].strip())
        names.append(line.split('-')[1].strip())
        indexes.append(line.split('-')[2].strip())
   

we_are='Alice'
they_are='Bob'
num_of_total_files=100
sc=SC() #object for symmetric crypto functions

in_pipe='../'+they_are+'_out_'+we_are+'_in'
out_pipe='../'+we_are+'_out_'+they_are+'_in'

#open pipes
sc.rp=open(in_pipe, 'r')
sc.wp=open(out_pipe,'w')


#get the hashes of our files
hashes=[] #the hashes in hex
indexes=[] #the indexes of the files in the directory
names=[]  #the names of the files
print("Finding hashes, names and indexes of our files...")
find_hashes_names_indexes_of_our_files()
print("Found them.")






#construct Elgamal public key for communication (or use the one that has already been created)
asymmetric_keypair_file = Path("./Alice_asymmetric_keypair")
if asymmetric_keypair_file.is_file():
    print("Fetching asymmetric keypair from file...")
    pubkey = pickle.load( open( "Alice_asymmetric_keypair", "rb" ) ) #load it from te file
    print("ElGamal key loaded.")
else:
    print("No file with asymmetric keypair data found. Generating public key for communication...")
    print("This will take some time, for keysize 2048 bits (~5 mins). Meanwhile, you can watch this video: http://youtu.be/msX4oAXpvUE :)")
    pubkey = ElGamal.generate(2048, Random.new().read)
    print("ElGamal key generated.")
    pickle.dump( pubkey, open( "Alice_asymmetric_keypair", "wb" ) ) #put it in a file

#print(pubkey.p) #prime
#print(pubkey.g) #generator
#print(pubkey.y) #public key
#print(pubkey.x) #private key


print("Sending the public key and g,p. We assume this part is not tampered with.")
sc.unsafe_send(sc.turn_str_into_byte_string_of_same_value(str(pubkey.p)+"\n"))
sc.unsafe_send(sc.turn_str_into_byte_string_of_same_value(str(pubkey.g)+"\n"))
sc.unsafe_send(sc.turn_str_into_byte_string_of_same_value(str(pubkey.y)+"\n"))
#close_and_reopen_write_pipe()
print("Sent the public key and the other parameters.")


print("Receiving AES key and authentication key...")
aes_key_mac=sc.turn_byte_string_into_normal_str(sc.unsafe_recv()+sc.unsafe_recv())
aes_key_mac_list=aes_key_mac.split("\n")
aes_key_mac_list= list(filter(None, aes_key_mac_list)) #Remove empty strings from list of strings
aes_key_mac_encrypted_1=base64.b64decode(aes_key_mac_list[0]) #decode base64
aes_key_mac_encrypted_2=base64.b64decode(aes_key_mac_list[1])
aes_key_mac_decrypted=pubkey.decrypt((aes_key_mac_encrypted_1,aes_key_mac_encrypted_2)).decode('utf-8')
aes_key=int(aes_key_mac_decrypted.split("|")[0].strip())
mac_key=int(aes_key_mac_decrypted.split("|")[1].strip())


print(aes_key)
print(mac_key)
print("Received AES key and MAC key.")


print("From now on, all encryption will be done using symmetric crypto + nonces to protect from replay attacks.")


#write the hashes
print("Sending hashes...")
for hash_of_file in hashes:
    sc.secure_symmetric_send(hash_of_file+"\n",aes_key,mac_key)
print("Sent hashes.")


#close pipes
time.sleep(2)
sc.wp.close()
sc.rp.close()
