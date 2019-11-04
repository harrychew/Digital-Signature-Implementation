from Crypto.PublicKey import RSA
from Crypto import Random

#Generate Bob's public key and private key using RSA
key = RSA.generate(1024)
private_key_alice = key.exportKey() 
public_key_alice = key.publickey().exportKey()
print('Public key and private key generated!')
print("Alice's Public key is:\n", public_key_alice)
print("Alice's Private key is:\n", private_key_alice)


#Store Alice's public key and private key into respective file
PrivateKeyFile = open("AlicePrivateKeyFile.der", "wb")
PrivateKeyFile.write(private_key_alice)
PrivateKeyFile.close()

PublicKeyFile = open("AlicePublicKeyFile.der", "wb")
PublicKeyFile.write(public_key_alice)
PublicKeyFile.close()