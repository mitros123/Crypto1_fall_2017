#!/usr/bin/env python3 


import os
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

class Symmetric_Crypto_Functions:

    def __init__(self):
        self.nonce=0
        self.wp=None
        self.rp=None
    

    def unsafe_send(self,msg):
        #puts msg in the "network", encoded
        self.wp.write(self.turn_byte_string_into_normal_str(base64.b64encode(msg))+"\n")
        self.wp.flush() #make sure the message is sent

    def unsafe_recv(self):
        #receives msg from the "network", encoded
        msg=self.rp.readline()
        msg=msg[:-1]
        return base64.b64decode(self.turn_str_into_byte_string_of_same_value(msg))

    def add_nonce_to_msg(self,msg):
        #msg is a normal string
        self.nonce+=1
        #what if msg contains "--->"??? We turn it into a byte string and encode it with base64, and then turn it back into string
        msg_as_bs=self.turn_str_into_byte_string_of_same_value(msg)
        return (str(self.nonce)+"--->"+self.turn_byte_string_into_normal_str(base64.b64encode(msg_as_bs))) #return value is a str once more

    def verify_nonce_of_msg(self,msg):
        #msg is a normal string
        nonce_recv=int(msg.split("--->")[0])
        if (nonce_recv!=self.nonce+1):
            sys.stderr.write("Error in nonce! wanted "+str(self.nonce+1)+" and got "+str(nonce_recv)+"\n")
            exit(-1)
        self.nonce+=1
        #we return a normal string. That is, we turn the part after the "--->" into bytestring, decode it with base64 and encode it back again
        msg_as_bs=self.turn_str_into_byte_string_of_same_value(msg.split("--->")[1])
        return (self.turn_byte_string_into_normal_str(base64.b64decode(msg_as_bs))) #return value is a str once more


    def close_and_reopen_write_pipe(self):
        #forces flush of data
        self.wp.close()
        time.sleep(0.25)
        self.wp=open(out_pipe,'w')

    def close_and_reopen_read_pipe(self):
        self.rp.close()
        time.sleep(0.25)
        self.rp=open(in_pipe,'r')


       
    def verify_hmac_of_msg_and_return_proper_msg(self,msg,mac_key):
        #msg is a byte string, mac_key is an integer. Returns a byte string
        proper_msg=msg.split(b"|")[0]
        hmac_of_msg=msg.split(b"|")[1]
        if (self.hmac(proper_msg,mac_key)!=self.turn_byte_string_into_normal_str(hmac_of_msg)):
            sys.stderr.write("Error in hmac! wanted "+self.hmac(proper_msg,mac_key)+" and got "+self.turn_byte_string_into_normal_str(hmac_of_msg)+"\n")
            exit(-1)
        return proper_msg 


    def turn_decimal_int_into_byte_string_of_same_value(self,dec_int):
        hex_repr=hex(dec_int).split("x")[1]
        if (len(hex_repr)%2==1):
            hex_repr="0"+hex_repr
        ret_str=bytes(bytearray.fromhex(hex_repr))
        return ret_str

    def turn_str_into_byte_string_of_same_value(self,str_in):
        return str_in.encode("utf-8")

    def turn_byte_string_into_normal_str(self,bytestr):
        return bytestr.decode("utf-8")
    
    def turn_int_into_byte_string_of_same_value(self,int_in):
        x=int_in
        return x.to_bytes((x.bit_length() + 7)//8, byteorder='big')

    def turn_byte_string_into_int_of_same_value(self,bytestr):
        return int.from_bytes(bytestr,byteorder='big')

    #https://www.dlitz.net/software/pycrypto/api/current/Crypto.Hash.HMAC-module.html
    def hmac(self,msg,mac_key):
        #returns mac of a message as a *normal* string. msg is a byte str, mac_key is an int
        secret_for_hmac=self.turn_decimal_int_into_byte_string_of_same_value(mac_key)
        h = HMAC.new(secret_for_hmac,digestmod=SHA256)
        h.update(msg)
        return h.hexdigest()

    #https://stackoverflow.com/questions/14179784/python-encrypting-with-pycrypto-aes
    def pad_data(self,data):
        #data is a byte string
        length = AES.block_size - (len(data) % AES.block_size)
        ret_data =data+ bytes([length])*length
        return ret_data

    def unpad_data(self,data):
        #data is a byte string
        ret_data= data[:-data[-1]]
        return ret_data

    #https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
    def encrypt_aes_cbc(self,str_to_encrypt,aes_key):
        #str_to_encrypt is a normal string. aes_key is an integer
        byte_str_to_encrypt=self.turn_str_into_byte_string_of_same_value(str_to_encrypt)
        byte_str_to_encrypt=self.pad_data(byte_str_to_encrypt)
        iv = Random.new().read( AES.block_size )
        aes_key_as_byte_str=self.turn_decimal_int_into_byte_string_of_same_value(aes_key)
        #now byte_str_to_encrypt, iv, aes_key_as_byte_str are all byte strings
        cipher = AES.new( aes_key_as_byte_str, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( byte_str_to_encrypt ) ) 
        
    def decrypt_aes_cbc(self,str_to_decrypt,aes_key):
        #str_to_encrypt is a byte string. aes_key is an integer. Returns a byte string
        enc = base64.b64decode(str_to_decrypt)
        iv = enc[:AES.block_size]
        aes_key_as_byte_str=self.turn_decimal_int_into_byte_string_of_same_value(aes_key)
        cipher = AES.new(aes_key_as_byte_str, AES.MODE_CBC, iv )
        return self.unpad_data(cipher.decrypt( enc[AES.block_size:] ))


    def secure_symmetric_send(self,msg,aes_key,mac_key):
        #msg is a normal string, and the keys are integers
        new_msg=self.add_nonce_to_msg(msg) #new_msg is a normal string
        new_msg=self.encrypt_aes_cbc(new_msg,aes_key) #new_msg is a byte string now (the output of base64), and remains as such
        new_msg=new_msg+b'|'+self.turn_str_into_byte_string_of_same_value(self.hmac(new_msg,mac_key)) #encrypt-then-mac
        self.unsafe_send(new_msg)

    def secure_symmetric_recv(self,aes_key,mac_key):
        #the keys are integers
        msg=self.unsafe_recv() #msg is a byte string
        msg=self.verify_hmac_of_msg_and_return_proper_msg(msg,mac_key) #msg is still a byte string
        msg=self.decrypt_aes_cbc(msg,aes_key) #msg is still a byte string
        msg=self.turn_byte_string_into_normal_str(msg) #now msg becomes a normal string
        msg=self.verify_nonce_of_msg(msg)
        return msg
