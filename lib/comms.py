import struct
import base64
import time
import socket

from Crypto import Random
from Crypto.Cipher import AES

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

from dh import create_dh_key, calculate_dh_secret


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.block_size = 16
        self.botsecret = "Security is fun'da'mental".encode()
        self.key = None
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

        # Store the key to use for AES
        self.key = bytes.fromhex(shared_hash)
        # Create a Message Secret to use for this session
        # This is used to HMAC each message sent
        # Use the session key to HMAC the bot secret to generate the Message Session secret
        hmac = HMAC.new(self.key, digestmod=SHA256)
        hmac.update(self.botsecret)
        self.msgsecret = hmac.digest()
        

    def send(self, data):
        if self.key:
            #Encript Data using function for AES
            encrypted_data = self.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        try:
            # Decode the data's length from an unsigned two byte int ('H')
            pkt_len_packed = self.conn.recv(struct.calcsize('H'))
            unpacked_contents = struct.unpack('H', pkt_len_packed)
            pkt_len = unpacked_contents[0]
            encrypted_data = self.conn.recv(pkt_len)
            if self.key:
                #decrypt the data using the decrypt function for AES
                data = self.decrypt(encrypted_data)
                if self.verbose:
                    print("Receiving packet of length {}".format(pkt_len))
                    print("Encrypted data: {}".format(repr(encrypted_data)))
                    print("Original data: {}".format(data))
                    
            else:
                data = encrypted_data
                
            return data
        except struct.error:
            # To Deal with revived packets that arent in the correct format.
            print("An Error Occured When Revicing Packet")
            raise socket.error("An Error Occured When Revicing Packet")
            

    def close(self):
        self.conn.close()

    # This is a function to enrypt the data and to arange a message into a packet
    # The packet order is: [MAC IV {Time Message}] where {} is encrypted
    # All but the message have known fixed lengths
    def encrypt(self, msg):
        # if message is string encode it
        if isinstance(msg, str):
            msg = msg.encode()

        # store the time in a 4 byte unsigned long
        sentTime = struct.pack('L', int(time.time()))

        # Append the msg to the time 
        tmsg = sentTime + msg;
        
        # Pad data into lengths of 16 bytes (blocks)
        paded = self.pad(tmsg)
        
        # Create a new 16 Byte random int
        iv = Random.new().read(AES.block_size)

        # Create a new Cipher with our key and IV
        cipher = AES.new(self.key, AES.MODE_OFB, iv)

        # Encrypt the data using AES and our Random IV in OFB mode
        eyp = cipher.encrypt(paded)

        # Append the encypted data to the IV
        ive = iv + eyp

        # Generate a HMAC of the current message using our message session secret
        hmac = HMAC.new(self.msgsecret, digestmod=SHA256)
        hmac.update(ive)
        mac = hmac.digest()

        # Append the current IV and encrypted data to the MAC
        macm = mac + ive

        # Encode the combind message
        enc = base64.b64encode(macm)      

        # Return the encoded message
        return enc;
    
    # This function is used to unpack the packet and validate it
    # Only valid message are returned decrypted
    def decrypt(self, enc):
        
        # Decode the encoded message
        macm = base64.b64decode(enc)

        # Exstract the MAC from the message
        mac = macm[:32]

        # Exstract the IV and encypted data
        ive = macm[32:]

        # Generate a HMAC of the current IV and encrypted data using our message session secret
        hmac = HMAC.new(self.msgsecret, digestmod=SHA256)
        hmac.update(ive)
        ourmac = hmac.digest()
        
        # Check to see if the MAC's are the same
        # This checks 2 things:
        # If bit fliping and tampering with message has occured,
        # If message is coming from a Bot
        # IF MAC's are not the same then close connection and error out
        if mac == ourmac:
            print("Messsage is from a Bot")
        else:
            self.close()            
            raise socket.error("MAC's Dont Match")

                
        # Extract the IV
        iv = ive[:self.block_size]

        # Extract the encrypted data
        eyp = ive[self.block_size:]
        
        #Create a new AES cipher with the IV and key in OFB mode
        cipher = AES.new(self.key, AES.MODE_OFB, iv)
        
        # Decrypt the data
        paded = cipher.decrypt(eyp)

        # Unpad the data the padded data
        tmsg = self.unpad(paded)

        # Exstract the time from the data and get the current time
        sentTime = struct.unpack('L', tmsg[:4])[0]
        currentTime = int(time.time())
        timeDiff = currentTime - sentTime;
        
        # Check the time difference
        # If message is more than 30 sec, close connection and error out
        if(timeDiff <= 30):
            print("Message Time Difference: " +str(timeDiff) + " s")
        else:
            self.close()
            raise socket.error("Packet is to old")

        # Exstract the message
        msg = tmsg[4:]

        # Return the message
        return msg

    # This function is used to padd a byte string into blocks if 16 bytes
    # This is a standard function that can be found on the internet
    # It has been slightly modified to work with byte string
    def pad(self, s):
        return s + (self.block_size - len(s) % self.block_size) * chr(self.block_size - len(s) % self.block_size).encode()

    # This function is used to remove padding at the end of a byte string
    # This function also can be found on the internet
    def unpad(self, s):
        return s[:-ord(s[len(s)-1:])]
