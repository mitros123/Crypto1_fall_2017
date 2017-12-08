<h1>Crypto 1 Project Fall 2017, RPI</h1>

Students: Akshay Bhazin (bhasia@rpi.edu)
Konstantinos Mitropoulos (mitros123@hotmail.com)

Packages needed: python3-crypto

<h3>Story</h3>
Alice and Bob have many files. They want to compare if some of them are equal. They only want to disclose if two are equal or not, and no more info, if possible.
They also want to communicate over a secure channel, so as that no eavesdropper can understand what they are saying.

<h3>Assumptions</h3>
**i)** We assume that Alice and Bob are semi-honest, that means that they follow the protocol but they will try to calculate extra stuff afterwards. We want to minimize the information that is leaked.
**ii)** We can't use MPC or Zero-Knowledge Proofs, only up to ElGamal asymmetric encryption and its homomorphic properties. 
**iii)** We assume that SHA256 is a collision resistant hash.
**iv)** We assume that HMAC-SHA256 is a good MAC.
**v)** We assume that AES is a good encryption primitive.
**vi)** We assume that Bob knows Alice's public key (and the corresponding generator g and prime p). We simply send them at the start, we assume these are not tampered with. 


<h3>How to run</h3>
**i)** cd to project_code and run init_structure.sh. This will create the files whose hashes we compare. Default is 100 files, 80 distinct and 20 common (their names imply their property).
It also creates two named pipes. One is for Alice's output/Bob's input, and the other for Bob's output/Alice's input. This is the "channel" they communicate over, and we consider it unsecure.
**ii)** Open two separate terminals. One should cd into Alice's directory, the other into Bob's directory.
**iii)** Run ./Bob_script_that_achieves_secure_comparison_of_files.py and ./Alice_script_that_achieves_secure_comparison_of_files.py. At the first time Alice will generate keys, and it will take some time.
**iv)** Watch the output.

<h3>Secure communication</h3>
With Alice's public key, Bob samples two random integers from {1 ... 2^128-1} and sends them (encrypted) to Alice. They are the encryption and the authentication keys.
After that, they start communication with symmetric crypto (the functions are in project_code/symmetric_crypto_functions.py). They use nonces for defence against replay attacks, encryption with AES-CBC (with a random IV) and then authentication with HMAC-SHA256 (Encrypt-then-MAC).

<h3>Secure hash comparison</h3>
Assume we need to compare the two hashes of two files, m1 (Alice) and m2 (Bob).
Alice generates an ElGamal key, and sends the public key to Bob, as well as the generator g and prime p. Let g^x be the public key, and x the private key.
She encrypts her message m1 with this key, ands sends the encryption to Bob: g^y,m1*g^(xy)
Bob samples a random value r1 from {1 ... p-1}, and calculates the inverse of m2. He multiplies them (m2^(-1)*r1) and encrypts them with the public key of Alice.
Bob has in his hands the encryption : g^(y'),m2^(-1)*r1*g^(xy')
He multiplies the two ciphertexts in order to get the product of the plaintexts, encrypted (homomorphic encryption).
He sends to Alice the product: g^(y+y'),m1*m2^(-1)*r1*g^(x(y+y')), as well as g^r1.
Alice decrypts and receives m1*m2^(-1)*r1 . If m1=m2, then she has r1 in her hands. She puts it into the exponent of g, and compares her own version of g^r1 with the one she received from Bob. If they are equal, the hashes are equal too. She sends "Yes" to Bob. If the two versions are not equal, then she sends "No".
Remember: Alice cannot lie (she has to follow the protocol from the assumptions). We could also do the symmetric from Bob's side, or use proper MPC/ZKP.

If m1!=m2, Alice will have a product in her hands that contains m2. If she knew r1. she could find it. However, g^r1 should not give enough information on r1 so as it allows Alice to find m2. That of course is an extra assumption that we make, and while it makes sense, we cannot be absolutely sure about it. It is the best that we can do however, if we don't use MPC/ZKP.


