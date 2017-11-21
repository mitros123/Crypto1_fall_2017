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


print("Fetching generator and modulus for hash comparison (or waiting until they are created)...")
#the generator g and prime p are created by Alice, for convenience. However, we assume that they have been agreed upon by the two parties. It's the same as hardcoding them into the program. 
name_of_generator_and_modulus_file="../generator_and_modulus_file"
generator_and_modulus_file = Path(name_of_generator_and_modulus_file)
while (generator_and_modulus_file.is_file()==False):
    time.sleep(1)
#and when the waiting is over
pubkey = pickle.load( open( name_of_generator_and_modulus_file, "rb" ) ) #load it from the file

print("Received generator and modulus.")

g=int(pubkey.g) #generator
p=int(pubkey.p) #prime, for modulus


same_hashes_ind=[]
#compare the hashes protocol: for every hash m1, send m1*r1, g^r1

print("Generating crypto numbers that will be sent...")
#generate the crypto numbers that will be sent
numbers_for_our_hashes=[]
for j,hash_of_file in enumerate(hashes):
    r2=random.StrongRandom().randint(1,p-1)
    g_pow_r2=pow(g,r2,p)
    hash_as_num=int(hash_of_file,16)%p
    m2invr2=(inverse(hash_as_num,p)*r2)%p
    numbers_for_our_hashes.append((r2,g_pow_r2,hash_as_num,m2invr2))

#simple 2*n messages and comparison for equality in n^2. Can be done in n*log(n).    
#send our hidden hash each time, for Alice to receive.
print("Sending our hidden hashes...")
for j,hash_of_file in enumerate(hashes):
    r2,g_pow_r2,hash_as_num,m2invr2=numbers_for_our_hashes[j]
    sc.secure_symmetric_send(str(m2invr2)+" "+str(g_pow_r2)+"\n",aes_key,mac_key)

print("Receiving Alice's hashes...")
#Receive messages from Alice
alice_msgs=[]
for i in range(num_of_total_files):
    alice_msg=sc.secure_symmetric_recv(aes_key,mac_key).strip()
    m1r1=int(alice_msg.split(" ")[0])
    g_pow_r1=int(alice_msg.split(" ")[1])
    alice_msgs.append((m1r1,g_pow_r1))

print("Comparing hashes...")
#check if the two hashes are the same. Is g^(m1*r1*m2^(-1)*r2) equal to g^(r1*r2)? Todo: in n*log(n)
for j,hash_of_file in enumerate(hashes):
    print(str(j+1)+"/"+str(num_of_total_files))
    r2,g_pow_r2,hash_as_num,m2invr2=numbers_for_our_hashes[j]
   
    for i in range(num_of_total_files):
        (m1r1,g_pow_r1)=alice_msgs[i]
        mult_all=(m2invr2*m1r1)%p
        g_pow_mult_all=pow(g,mult_all,p)
        g_pow_r1r2=pow(g_pow_r1,r2,p)
        if (names[j]=='common_file_8' and i==5):
            print(mult_all)
            print(r2)
            print(p)
            print(g_pow_mult_all)
            print(g_pow_r1r2)
        if (g_pow_r1r2==g_pow_mult_all):
            #found equal hash
            print("oo")
            same_hashes_ind.append(j)
            break

print("Printing equal files:")
for index in same_hashes_ind:
    print(names[index])   


#close pipes
time.sleep(2)
sc.rp.close()
sc.wp.close()
