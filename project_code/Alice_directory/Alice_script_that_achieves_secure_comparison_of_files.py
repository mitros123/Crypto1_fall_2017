#!/usr/bin/env python3

#uses Elgamal from https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.ElGamal-module.html

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
name_of_asymmetric_keypair_file="Alice_asymmetric_keypair"
asymmetric_keypair_file = Path("./"+name_of_asymmetric_keypair_file)
if asymmetric_keypair_file.is_file():
    print("Fetching asymmetric keypair from file...")
    pubkey = pickle.load( open( name_of_asymmetric_keypair_file, "rb" ) ) #load it from the file
    print("ElGamal key loaded.")
else:
    print("No file with asymmetric keypair data found. Generating public key for communication...")
    print("This will take some time, for keysize 2048 bits (~5 mins). Meanwhile, you can watch this video: http://youtu.be/msX4oAXpvUE :)")
    pubkey = ElGamal.generate(2048, Random.new().read)
    print("ElGamal key generated.")
    pickle.dump( pubkey, open( name_of_asymmetric_keypair_file, "wb" ) ) #put it in a file

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



#construct Elgamal generator and modulus (or use the one that has already been created)
#We only need g and p. However, we havea function which does it for us (the ElGamal private/public key generator)
#the g,p created are going to be read by Bob too. It's as if the two parties have agreed on them (hardcoded into the program).
name_of_generator_and_modulus_file="../generator_and_modulus_file"
generator_and_modulus_file = Path(name_of_generator_and_modulus_file)
if generator_and_modulus_file.is_file():
    print("Fetching generator and modulus from file...")
    pubkey = pickle.load( open( name_of_generator_and_modulus_file, "rb" ) ) #load it from the file
    print("Generator and modulus loaded.")
else:
    print("No file with generator and modulus data found. Generating them...")
    print("This will take some time, for n=2048 bits (~5 mins). Meanwhile, you can watch this video: http://youtu.be/9sJUDx7iEJw :)")
    pubkey = ElGamal.generate(2048, Random.new().read)
    print("ElGamal key generated.")
    pickle.dump( pubkey, open( name_of_generator_and_modulus_file, "wb" ) ) #put it in a file


g=int(pubkey.g) #generator
p=int(pubkey.p) #prime, for modulus


same_hashes_ind=[]
#compare the hashes protocol: for every hash m1, send m1*r1, g^r1

print("Generating crypto numbers that will be sent...")
#generate the crypto numbers that will be sent
numbers_for_our_hashes=[]
for j,hash_of_file in enumerate(hashes):
    r1=random.StrongRandom().randint(1,p-1)
    g_pow_r1=pow(g,r1,p)
    hash_as_num=int(hash_of_file,16)%p
    m1r1=(r1*hash_as_num)%p
    numbers_for_our_hashes.append((r1,g_pow_r1,hash_as_num,m1r1))


#simple 2*n messages and comparison for equality in n^2. Can be done in n*log(n).
#receive Bob's messages
print("Receiving Bob's hashes...")
bob_msgs=[]
for i in range(num_of_total_files):
    bobs_msg=sc.secure_symmetric_recv(aes_key,mac_key).strip()
    m2invr2=int(bobs_msg.split(" ")[0])
    g_pow_r2=int(bobs_msg.split(" ")[1])
    bob_msgs.append((m2invr2,g_pow_r2))

print("Sending our hidden hashes...")
#send our hidden hash each time, for Bob to receive.
for j,hash_of_file in enumerate(hashes):
    (r1,g_pow_r1,hash_as_num, m1r1)=numbers_for_our_hashes[j]
    sc.secure_symmetric_send(str(m1r1)+" "+str(g_pow_r1)+"\n",aes_key,mac_key)

print("Comparing hashes...")
#check if the two hashes are the same. Is g^(m1*r1*m2^(-1)*r2) equal to g^(r1*r2)? Todo: in n*log(n)
for i in range(num_of_total_files):
    print(str(i+1)+"/"+str(num_of_total_files))
    (m2invr2,g_pow_r2)=bob_msgs[i]
        
    for j,hash_of_file in enumerate(hashes):
        (r1,g_pow_r1,hash_as_num, m1r1)=numbers_for_our_hashes[j]
        mult_all=(m2invr2*m1r1)%p
        g_pow_mult_all=pow(g,mult_all,p)
        g_pow_r1r2=pow(g_pow_r2,r1,p)
        if (names[j]=='common_file_8' and i==2):
            print(mult_all)
            print(r1)
            print(p)
            print(g_pow_mult_all)
            print(g_pow_r1r2)
        if (g_pow_r1r2==g_pow_mult_all):
            #found equal hash
            print("a")
            same_hashes_ind.append(j)
            break

print("Printing equal files:")
for index in same_hashes_ind:
    print(names[index])   


#close pipes
time.sleep(2)
sc.wp.close()
sc.rp.close()
