#!/usr/bin/env python3

import os
from pathlib import Path
import sys
from subprocess import Popen, PIPE
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import GCD,inverse
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


def elgamal_encrypt(msg,pubkey,g,p): #all ints, pubkey=g^x
    y=random.StrongRandom().randint(1,p-2)
    return((pow(g,y,p),(msg*pow(pubkey,y,p))%p))

def elgamal_decrypt(enc,g_pow_y,g,p,privkey): #all ints , privkey=x
    g_pow_xy=pow(g_pow_y,privkey,p)
    msg=(inverse(g_pow_xy,p)*enc)%p
    return msg


we_are='Bob'
they_are='Alice'
num_of_total_files=100
sc=SC() #object for symmetric crypto functions

in_pipe='../'+they_are+'_out_'+we_are+'_in'
out_pipe='../'+we_are+'_out_'+they_are+'_in'

#open pipes
sc.wp=open(out_pipe,'w')
sc.rp=open(in_pipe, 'r')


#get the hashes of our files
hashes=[] #the hashes in hex
indexes=[]  #the indexes of the files in the directory
names=[]    #the names of the files
print("Finding hashes, names and indexes of our files...")
find_hashes_names_indexes_of_our_files()
print("Found them.")



print("Fetching "+they_are+"'s public key info. We assume this part is not tampered with.")
pubkey_info=sc.turn_byte_string_into_normal_str(sc.unsafe_recv()+sc.unsafe_recv()+sc.unsafe_recv())
pubkey_list=pubkey_info.split("\n")
pubkey_list= list(filter(None, pubkey_list)) #Remove empty strings from list of strings
pubkey_of_other={}
pubkey_of_other["p"]=int(pubkey_list[0]) #prime
pubkey_of_other["g"]=int(pubkey_list[1]) #generator
pubkey_of_other["y"]=int(pubkey_list[2]) #public key
print("Got public key info.")


print("Generating symmetric key and authentication key for symmetric encryption...")
aes_key=random.StrongRandom().randint(1,2**128-1)
mac_key=random.StrongRandom().randint(1,2**128-1)
aes_key_mac_enc=ElGamal.ElGamalobj()
aes_key_mac_enc.p=pubkey_of_other["p"]; aes_key_mac_enc.g=pubkey_of_other["g"]; aes_key_mac_enc.y=pubkey_of_other["y"]; #set the El Gamal values
#https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.ElGamal.ElGamalobj-class.html#encrypt
#put them both in the same message
aes_key_mac_enc_num=aes_key_mac_enc.encrypt(sc.turn_str_into_byte_string_of_same_value(str(aes_key)+"|"+str(mac_key)),random.StrongRandom().randint(1,pubkey_of_other["p"]-2))

print(aes_key)
print(mac_key)

aes_key_mac_enc_num_b64_1=base64.b64encode(aes_key_mac_enc_num[0]).decode('utf-8') #encode in base64 before sending
aes_key_mac_enc_num_b64_2=base64.b64encode(aes_key_mac_enc_num[1]).decode('utf-8') 
print("Sending AES key and MAC key to the other party...")
sc.unsafe_send(sc.turn_str_into_byte_string_of_same_value(aes_key_mac_enc_num_b64_1+"\n"))
sc.unsafe_send(sc.turn_str_into_byte_string_of_same_value(aes_key_mac_enc_num_b64_2+"\n"))
#close_and_reopen_write_pipe() #make sure they arrive
print("Sent AES key and MAC key to the other party.")

print("From now on, all encryption will be done using symmetric crypto + nonces to protect from replay attacks.")






print("Fetching encryption values")
same_hashes_ind=[]
alice_enc_params=sc.secure_symmetric_recv(aes_key,mac_key)
public_key=int(alice_enc_params.split("|")[0].strip())
p=int(alice_enc_params.split("|")[1].strip())
g=int(alice_enc_params.split("|")[2].strip())


#compare the hashes protocol: for every hash m1, Alice calculates the enryption of m1. g^r,m1*g^(xr). She sends that to Bob.
#Bob creates the encryption of m2^(-1)*r1 (r1 is a random value) g^(r'), m2^(-1)*r1*g^(xr'). He multiplies by the encryption of m1, for the hmomomorphic encryption
#The result is g^(r+r'), m2^(-1)*r1*m1*g^(x(r+r')). Alice receives that and she decrypts. If m1,m2 are equal, the decryption is equal to r1.
#Bob sends g^r1, and Alice compares with her version of g^r1. If they are the same, she sends "Yes" to Bob. If not, she sends "No". Important: The assumptions
#do not permit Alice to lie.

for i in range(num_of_total_files):
    print(str(i+1)+"/"+str(num_of_total_files))
    alice_enc_hash=sc.secure_symmetric_recv(aes_key,mac_key)
    alice_enc_hash_value_1=int(alice_enc_hash.split("|")[0].strip())
    alice_enc_hash_value_2=int(alice_enc_hash.split("|")[1].strip())

    for j,hash_of_file in enumerate(hashes):
        hash_as_num=int(hash_of_file,16)
        #print(hash_as_num)
        r1=random.StrongRandom().randint(1,p-1)
        g_pow_r1=pow(g,r1,p)
        our_encrypted_hash=ElGamal.ElGamalobj()
        our_encrypted_hash.p=p; our_encrypted_hash.g=g; our_encrypted_hash.y=public_key;
        m2invr1=(inverse(hash_as_num,p)*r1)%p

        elgamal_values=our_encrypted_hash.encrypt(sc.turn_int_into_byte_string_of_same_value(m2invr1),random.StrongRandom().randint(1,p-2))
        elgamal_value_1=sc.turn_byte_string_into_int_of_same_value(elgamal_values[0])
        elgamal_value_2=sc.turn_byte_string_into_int_of_same_value(elgamal_values[1])
        '''
        #Or
        (g_pow_y_2,enc_2)=elgamal_encrypt(m2invr1,public_key,g,p)
        elgamal_value_1=enc_2
        elgamal_value_2=g_pow_y_2  
        '''          

        homom_enc_value_1=(alice_enc_hash_value_1*elgamal_value_1)%p
        homom_enc_value_2=(alice_enc_hash_value_2*elgamal_value_2)%p
 
        sc.secure_symmetric_send(str(homom_enc_value_1)+"|"+str(homom_enc_value_2),aes_key,mac_key)
        sc.secure_symmetric_send(str(g_pow_r1),aes_key,mac_key)
        reply=sc.secure_symmetric_recv(aes_key,mac_key)
        if(reply=="Yes"):
            same_hashes_ind.append(j)
            print("Common hash: index:"+str(j+1)+", name: "+str(names[j]))
        
        

print("Printing equal files:")
for index in same_hashes_ind:
    print(names[index])   


#close pipes
time.sleep(2)
sc.rp.close()
sc.wp.close()
