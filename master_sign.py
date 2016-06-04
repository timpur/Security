import os
import struct

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def sign_file(file):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!

    
    hashfile = SHA256.new(file)
    key = RSA.importKey(open('private.pem').read())
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(hashfile)

    #Schema
    length = struct.pack('H', len(signature))
    file = length + signature + file
    
    return file


def generagteKey():
    new_key = RSA.generate(2048) 
    public_key = new_key.publickey().exportKey("PEM") 
    private_key = new_key.exportKey("PEM")

    publicfile = open('public.pem','wb')
    publicfile.write(public_key)
    publicfile.close()

    privatefile = open('private.pem','wb')
    privatefile.write(private_key)
    privatefile.close()

if __name__ == "__main__":
    
    #generagteKey()
    
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)




