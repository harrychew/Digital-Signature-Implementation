import tkinter as tk
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import codecs
from base64 import b64decode, b64encode 
import time
import cryptography 
import ast 
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
from tkinter import Listbox


#def run_process():
    #next = tk.Tk()
    #tk.Label(next, text="Input text").grid(row=0)
    #e1 = tk.Entry(next)
    #e1.grid(row=0, column=1)
    #tk.Button(next, text='Back', command=master).grid(row=3, column=0, sticky=tk.W, pady=4)
    #tk.Button(next, text='Enter', command=run_process2).grid(row=3, column=1, sticky=tk.W, pady=4)
    #next.mainloop()

    
def run_process():
    def sign(privatekey,hash):
      signer = PKCS1_v1_5.new(privatekey)
      sign = signer.sign(hash)
      return b64encode(sign)

    def encrypt(publickey,plaintext):
      key=PKCS1_OAEP.new(publickey)
      cipher_text=key.encrypt(plaintext)
      return b64encode(cipher_text)

    def decrypt(privatekey,ciphertext):
      key=PKCS1_OAEP.new(privatekey)
      plaintext=key.decrypt(b64decode(ciphertext))
      return plaintext


    def verify(publickey,hash2,signature): 
      verifier = PKCS1_v1_5.new(publickey)  
      verified = verifier.verify(hash2,b64decode(signature))
      if verified == True:
        return "Signature is valid!"
      else:
        return "Signature is not valid!"

    def integrity(hash1,received_hash):
      if hash1==received_hash:
        return "Message is not compromised"
      else:
        return "Message is compromised!"


    msg =e1.get().encode('utf-8')
    hashed = SHA256.new(msg)
    sign= sign(priv_key_a,hashed)
    bundle=msg+b'`'+hashed.digest()
    encrypted_bundle = encrypt(pub_key_b,bundle)
    #Store signature into file
    SignatureFile = open("AliceSignatureFile.txt", "wb")
    SignatureFile.write(sign)
    SignatureFile.close()
    #Store message into file
    MessageFile=open("AliceEncryptedMessageFile.txt","wb")
    MessageFile.write(encrypted_bundle)
    MessageFile.close()
    print("++++++++++++++++++++++++++++START OF ENCRYPTION++++++++++++++++++++++++++++++++")
    print("Message: \n", msg)
    print("Hash value: \n",hashed.digest())
    print('Signature is \n', sign)
    print('Bundle is \n', bundle)
    print("Encrypted bundle is: \n",encrypted_bundle)
    print("++++++++++++++++++++++++++++END OF ENCRYPTION++++++++++++++++++++++++++++++++++")
    a = 'Message: \n'
    b = 'Hash value: \n'
    c = 'Signature is \n'
    d = 'Bundle is \n'
    e = 'Encrypted bundle is: \n'

    o = a+str(msg)+'\n'+b+str(hashed.digest())+'\n'+c+str(sign)+'\n'+d+str(bundle)+'\n'+e+str(encrypted_bundle)
    tk.messagebox.showinfo("Signing and Encrypting......",o)
    e1.delete(0, tk.END)

def run_process2():
	try:
	    def sign(privatekey,hash1):
	      signer = PKCS1_v1_5.new(privatekey)
	      sign = signer.sign(hash1)
	      return b64encode(sign)
	      
	    def encrypt(publickey,plaintext):
	      key=PKCS1_OAEP.new(publickey)
	      cipher_text=key.encrypt(plaintext)
	      return b64encode(cipher_text)
	      
	    def decrypt(privatekey,ciphertext):
	      key=PKCS1_OAEP.new(privatekey)
	      plaintext=key.decrypt(b64decode(ciphertext))
	      return plaintext
	      
	    def integrity(hash1,received_hash):
	      if hash1==received_hash:
	        return "Message is not compromised"
	      else:
	        return "Message is compromised!"
	        
	    def verify(publickey,hash2,signature): 
	      verifier = PKCS1_v1_5.new(publickey)  
	      verified = verifier.verify(hash2,b64decode(signature))
	      if verified == True:
	        return "Signature is valid!"
	      else:
	        return "Signature is not valid!"

	    
	    MessageFile=open("BobEncryptedMessageFile.txt","r+")
	    encrypted_bundle1=MessageFile.read()
	    MessageFile.close()
	    SignatureFile = open("BobSignatureFile.txt", "r+")
	    sign=SignatureFile.read()
	    SignatureFile.close()
	    print(encrypted_bundle1)
	    decrypted_bundle=decrypt(priv_key_a,encrypted_bundle1)
	    decrypted_message=decrypted_bundle.split(b'`',1)[0]
	    removespace=decrypted_bundle.replace(b'`',b'')
	    decrypted_hash=removespace.replace(decrypted_message,b'')

	    hashed2 = SHA256.new(decrypted_message)
	    integrity=integrity(hashed2.digest(),decrypted_hash)
	    verified_msg= verify(pub_key_b,hashed2,sign)
	    print("++++++++++++++++++++++++++++START OF DECRYPTION++++++++++++++++++++++++++++++++")
	    print('Signature is \n', sign)
	    print("Encrypted bundle is: \n",encrypted_bundle1)

	    print("Decrypted bundle is: \n",decrypted_bundle)
	    print('Decrypted hash:\n', decrypted_hash)
	    print('Decrypted message:\n', decrypted_message)
	    print('Second hash: \n',hashed2.digest())

	    print('Verifying message integrity by comparing with received hash and hash generated from received message....')
	    print('Message integrity status:', integrity)
	    print('Verifying signature authenticity using Alice public key ........')
	    print("Verified status:", verified_msg)
	    print("++++++++++++++++++++++++++++END OF DECRYPTION++++++++++++++++++++++++++++++++++")
	    a1= 'Getting Bob Signature and Encrypted bundle...\n'
	    c = 'Signature is \n'
	    e = 'Received bundle is: \n'
	    f = 'Decrypted bundle is: \n'
	    g = 'Decrypted hash:\n'
	    h = 'Decrypted message:\n'
	    i = 'Second hash:\n'
	    j = 'Verifying message integrity by comparing with received hash and hash generated from received message....\n'
	    k = 'Message integrity status:'
	    l = 'Received Signature:\n'
	    m = 'Verifying signature authenticity using Alice public key ........\n'
	    n = 'Verified status:'

	    o = a1+c+str(sign)+'\n'+e+str(encrypted_bundle1)+'\n'+f+str(decrypted_bundle)+'\n'+g+str(decrypted_hash)+'\n'+h+str(decrypted_message)+'\n'+i+str(hashed2.digest())+'\n'+j+k+str(integrity)+'\n'+l+str(sign)+'\n'+m+n+str(verified_msg)

	    tk.messagebox.showinfo("Decrypting and verifying......",o)
	    e1.delete(0, tk.END)
	except (ValueError) as e:
		print("Incoming Message has been compromised!")
		a="Incoming Message has been compromised!"
		tk.messagebox.showinfo("Status",a)
		e1.delete(0, tk.END)


master = tk.Tk()
master.title('Alice')
tk.Label(master, text="Notice: ").grid(row=0)
#get Bob's public key file
BobPublicKeyFile=open("BobPublicKeyFile.der","r+")
public_key_bob=BobPublicKeyFile.read()
BobPublicKeyFile.close()
pub_key_b=RSA.importKey(public_key_bob)
print("Done! Bob's public key received!")
tk.Label(master, text="Bob's public key received!").grid(row=1)

#get Alice's public key file
AlicePublicKeyFile=open("AlicePublicKeyFile.der","r+")
public_key_alice=AlicePublicKeyFile.read()
AlicePublicKeyFile.close()
pub_key_a=RSA.importKey(public_key_alice)
print("Done! Alice's public key received!")
tk.Label(master, text="Alice's public key received!").grid(row=2)
#get Alice's private key file
AlicePrivateKeyFile=open("AlicePrivateKeyFile.der","r+")
private_key_alice=AlicePrivateKeyFile.read()
AlicePublicKeyFile.close()
priv_key_a=RSA.importKey(private_key_alice)
print("Done! Alice's private key received!")
tk.Label(master, text="Alice's private key received!").grid(row=3)
tk.Label(master, text="_______________________________________").grid(row=4)
tk.Label(master, text="What you want to do? ").grid(row=5)

tk.Label(master, text="Send Message to Bob").grid(row=7)
e1 = tk.Entry(master)
e1.grid(row=8, column=0)

tk.Label(master, text=" ").grid(row=9)
tk.Label(master, text="OR").grid(row=10)
tk.Label(master, text=" ").grid(row=11)
tk.Label(master, text="Click NEXT to verify message from Bob").grid(row=12)
tk.Button(master, text='Quit', command=master.quit).grid(row=13, column=0, sticky=tk.W, pady=4)
tk.Button(master, text='OK', command=run_process).grid(row=8, column=1, sticky=tk.W, pady=4)
tk.Button(master, text='Next', command=run_process2).grid(row=13, column=2, sticky=tk.W, pady=4)

master.mainloop()

tk.mainloop()

