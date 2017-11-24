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
   

def elgamal_encrypt(msg,pubkey,g,p): #all ints, pubkey=g^x
    y=random.StrongRandom().randint(1,p-2)
    return((pow(g,y,p),(msg*pow(pubkey,y,p))%p))

def elgamal_decrypt(enc,g_pow_y,g,p,privkey): #all ints , privkey=x
    g_pow_xy=pow(g_pow_y,privkey,p)
    msg=(inverse(g_pow_xy,p)*enc)%p
    return msg
    
    
    

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



#construct Elgamal public, private key, generator and modulus (or use the one that has already been created)
name_of_hash_hiding_key_file="hash_hiding_key_file"
hash_hiding_key_file = Path(name_of_hash_hiding_key_file)
if hash_hiding_key_file.is_file():
    print("Fetching generator and modulus from file...")
    pubkey = pickle.load( open( name_of_hash_hiding_key_file, "rb" ) ) #load it from the file
    print("Generator and modulus loaded.")
else:
    print("No file with generator and modulus data found. Generating them...")
    print("This will take some time, for n=2048 bits (~5 mins). Meanwhile, you can watch this video: http://youtu.be/9sJUDx7iEJw :)")
    pubkey = ElGamal.generate(2048, Random.new().read)
    print("ElGamal key generated.")
    pickle.dump( pubkey, open( name_of_hash_hiding_key_file, "wb" ) ) #put it in a file


g=int(pubkey.g) #generator
p=int(pubkey.p) #prime, for modulus
public_key=int(pubkey.y)
priv_key=int(pubkey.x)

#send public key, prime, generator to Bob
sc.secure_symmetric_send(str(public_key)+"|"+str(p)+"|"+str(g),aes_key,mac_key)


same_hashes_ind=[]
#compare the hashes protocol: for every hash m1, Alice calculates the enryption of m1. g^r,m1*g^(xr). She sends that to Bob.
#Bob creates the encryption of m2^(-1)*r1 (r1 is a random value) g^(r'), m2^(-1)*r1*g^(xr'). He multiplies by the encryption of m1, for the hmomomorphic encryption
#The result is g^(r+r'), m2^(-1)*r1*m1*g^(x(r+r')). Alice receives that and she decrypts. If m1,m2 are equal, the decryption is equal to r1.
#Bob sends g^r1, and Alice compares with her version of g^r1. If they are the same, she sends "Yes" to Bob. If not, she sends "No". Important: The assumptions
#do not permit Alice to lie.

print("Generating crypto numbers that will be sent...")
numbers_for_our_hashes=[]
for j,hash_of_file in enumerate(hashes):
    print(str(j+1)+"/"+str(num_of_total_files))
    hash_as_num=int(hash_of_file,16)
    encrypted_hash=ElGamal.ElGamalobj()
    encrypted_hash.p=p; encrypted_hash.g=g; encrypted_hash.y=public_key; encrypted_hash.x=priv_key;

    #https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.ElGamal.ElGamalobj-class.html#encrypt
    elgamal_values=encrypted_hash.encrypt(sc.turn_int_into_byte_string_of_same_value(hash_as_num),random.StrongRandom().randint(1,p-2))
    elgamal_value_1=sc.turn_byte_string_into_int_of_same_value(elgamal_values[0])
    elgamal_value_2=sc.turn_byte_string_into_int_of_same_value(elgamal_values[1])
    '''
    #Or
    (g_pow_y_1,enc_1)=elgamal_encrypt(hash_as_num,public_key,g,p)
    elgamal_value_1=enc_1
    elgamal_value_2=g_pow_y_1
    '''

    sc.secure_symmetric_send(str(elgamal_value_1)+"|"+str(elgamal_value_2)+"\n",aes_key,mac_key)
    #print(elgamal_value_1,elgamal_value_2)

    for i in range(num_of_total_files):
        #receive Bob's homomorphic encryption of both messages
        homom_enc=sc.secure_symmetric_recv(aes_key,mac_key)
    
        first_part_of_enc=sc.turn_int_into_byte_string_of_same_value(int(homom_enc.split("|")[0].strip()))
        second_part_of_enc=sc.turn_int_into_byte_string_of_same_value(int(homom_enc.split("|")[1].strip()))
        #https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.ElGamal.ElGamalobj-class.html#decrypt
        homom_dec=encrypted_hash.decrypt((first_part_of_enc,second_part_of_enc))
        homom_dec_num=sc.turn_byte_string_into_int_of_same_value(homom_dec)
        '''
        #Or
        first_part_of_enc=int(homom_enc.split("|")[0].strip())
        second_part_of_enc=int(homom_enc.split("|")[1].strip())
        homom_dec_num=elgamal_decrypt(first_part_of_enc,second_part_of_enc,g,p,priv_key)
        '''
        
        g_pow_r1=int(sc.secure_symmetric_recv(aes_key,mac_key))
        mult_all=homom_dec_num%p
        g_pow_mult_all=pow(g,mult_all,p)
        reply="No"
        if (g_pow_r1==g_pow_mult_all):
            print("Common hash: index:"+str(j+1)+", name: "+str(names[j]))
            same_hashes_ind.append(j)
            reply="Yes"
        sc.secure_symmetric_send(reply,aes_key,mac_key)

print("Printing equal files:")
for index in same_hashes_ind:
    print(names[index])   


#close pipes
time.sleep(2)
sc.wp.close()
sc.rp.close()
