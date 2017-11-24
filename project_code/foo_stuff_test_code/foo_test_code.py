'''
print("second try...")
            msg=424242424242424242424242424242;
            (g_pow_y,enc)=elgamal_encrypt(msg,pow(g,priv_key,p),g,p)
            #print(elgamal_decrypt(enc,g_pow_y,g,p,priv_key))
            
            r2=random.StrongRandom().randint(1,2**256-1)
            g_pow_r2=pow(g,r2,p)
            m2invr2=(inverse(hash_as_num,p)*r2)
        
            #print(m2invr2)
            #print(m2invr2*hash_as_num)
            #print(m2invr2%p*hash_as_num)
            print((m2invr2%p*hash_as_num)%p)  #correct
            print((m2invr2*hash_as_num)%p) #correct
            
            m2invr2=m2invr2%p
            #elgamal_values2=encrypted_hash.encrypt(sc.turn_int_into_byte_string_of_same_value(m2invr2),random.StrongRandom().randint(1,p-2))
            #elgamal_value2_1=sc.turn_byte_string_into_int_of_same_value(elgamal_values2[0])
            #elgamal_value2_2=sc.turn_byte_string_into_int_of_same_value(elgamal_values2[1])
            (g_pow_y_2,enc_2)=elgamal_encrypt(m2invr2,pow(g,priv_key,p),g,p)
    
            #homom_enc_value_1=(elgamal_value2_1*elgamal_value_1) %p
            #homom_enc_value_2=(elgamal_value2_2*elgamal_value_2) %p
            #homom_bs1=sc.turn_int_into_byte_string_of_same_value(homom_enc_value_1)
            #homom_bs2=sc.turn_int_into_byte_string_of_same_value(homom_enc_value_2)
            hom_1=(g_pow_y_2*g_pow_y_1)%p
            hom_2=(enc_1*enc_2)%p
            homom_dec_num=elgamal_decrypt(hom_2,hom_1,g,p,priv_key)
            #homom_dec=encrypted_hash.decrypt((homom_bs1,homom_bs2))
            #homom_dec_num=sc.turn_byte_string_into_int_of_same_value(homom_dec)%p
            print(homom_dec_num)
            print(r2)
            '''
'''
#simple 2*n messages and comparison for equality in n^2. Can be done in n*log(n).
#receive Bob's messages
print("Receiving Bob's hashes...")
bob_msgs=[]
for i in range(num_of_total_files):
    bobs_msg=sc.secure_symmetric_recv(aes_key,mac_key).strip()
    m2invr2=int(bobs_msg.split(" ")[0])
    g_pow_r2=int(bobs_msg.split(" ")[1])
    r2=int(bobs_msg.split(" ")[2])
    bob_msgs.append((m2invr2,g_pow_r2,r2))

print("Sending our hidden hashes...")
#send our hidden hash each time, for Bob to receive.
for j,hash_of_file in enumerate(hashes):
    (r1,g_pow_r1,hash_as_num, m1r1)=numbers_for_our_hashes[j]
    sc.secure_symmetric_send(str(m1r1)+" "+str(g_pow_r1)+" "+str(r1)+"\n",aes_key,mac_key)

print("Comparing hashes...")
#check if the two hashes are the same. Is g^(m1*r1*m2^(-1)*r2) equal to g^(r1*r2)? Todo: in n*log(n)
for i in range(num_of_total_files):
    print(str(i+1)+"/"+str(num_of_total_files))
    (m2invr2,g_pow_r2,r2)=bob_msgs[i]
        
    for j,hash_of_file in enumerate(hashes):
        (r1,g_pow_r1,hash_as_num, m1r1)=numbers_for_our_hashes[j]
        mult_all=(m2invr2*m1r1)
        g_pow_mult_all=pow(g,mult_all,p)
        g_pow_r1r2=pow(g_pow_r2,r1,p)
        if (names[j]=='common_file_8' and i==2):
            print(mult_all)
            print((r1*r2))
            print(pow(g,(r1*r2),p))
            print(g_pow_mult_all)
            print(pow(pow(g,r1,p),r2,p))
            print(g_pow_r1r2)
        if (g_pow_r1r2==g_pow_mult_all):
            #found equal hash
            print("a")
            same_hashes_ind.append(j)
            break
'''



'''

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
    sc.secure_symmetric_send(str(m2invr2)+" "+str(g_pow_r2)+" "+str(r2)+"\n",aes_key,mac_key)

print("Receiving Alice's hashes...")
#Receive messages from Alice
alice_msgs=[]
for i in range(num_of_total_files):
    alice_msg=sc.secure_symmetric_recv(aes_key,mac_key).strip()
    m1r1=int(alice_msg.split(" ")[0])
    g_pow_r1=int(alice_msg.split(" ")[1])
    r1=int(alice_msg.split(" ")[2])
    alice_msgs.append((m1r1,g_pow_r1,r1))

print("Comparing hashes...")
#check if the two hashes are the same. Is g^(m1*r1*m2^(-1)*r2) equal to g^(r1*r2)? Todo: in n*log(n)
for j,hash_of_file in enumerate(hashes):
    print(str(j+1)+"/"+str(num_of_total_files))
    r2,g_pow_r2,hash_as_num,m2invr2=numbers_for_our_hashes[j]
   
    for i in range(num_of_total_files):
        (m1r1,g_pow_r1,r1)=alice_msgs[i]
        mult_all=(m2invr2*m1r1)%p
        g_pow_mult_all=pow(g,mult_all,p)
        g_pow_r1r2=pow(g_pow_r1,r2,p)
        if (names[j]=='common_file_8' and i==5):
            print(mult_all)
            print((r1*r2))
            print(pow(g,(r1*r2)%p,p))
            print(g_pow_mult_all)
            print(pow(pow(g,r1,p),r2,p))
            print(g_pow_r1r2)
        if (g_pow_r1r2==g_pow_mult_all):
            #found equal hash
            print("oo")
            same_hashes_ind.append(j)
            break
'''
