from Crypto.PublicKey import RSA
from Crypto import Random

#Generate Bob's public key and private key using RSA

key2 = RSA.generate(1024, Random.new().read)
private_key_bob = key2.exportKey() 
public_key_bob = key2.publickey().exportKey()
print('Public key and private key generated!')
print("Bob's Public key is:\n", public_key_bob)
print("Bob's Private key is:\n", private_key_bob)

#Store Bob's public key and private key into respective file
PrivateKeyFile = open("BobPrivateKeyFile.der", "wb")
PrivateKeyFile.write(private_key_bob)
PrivateKeyFile.close()

PublicKeyFile = open("BobPublicKeyFile.der", "wb")
PublicKeyFile.write(public_key_bob)
PublicKeyFile.close()