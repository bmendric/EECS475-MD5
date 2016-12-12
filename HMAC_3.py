#An implementation of HMAC, using MD5 as the hashing algorithm.

from b_md5 import *
import binascii

BLOCK_SIZE = 64 #MD5 input block size
BLOCK_SIZE_BITS = BLOCK_SIZE * 2 #Block size in bits (used zero-padding)
OPAD = int("5c" * 64, 16) #Constants chosen in 1996 paper on HMAC construction
IPAD = int("36" * 64, 16) 
KEY_PRIME = ""

KEY = b"Hello"
MESSAGE = b"World" 

# If key is longer than block size, set key = hash(original key)
if len(KEY) > 64:
	KEY_PRIME = pymd5.md5(KEY)
	
# If key is shorter, pad with zeros to blocksize
if len(KEY) < 64:
	KEY_PRIME = str(binascii.hexlify(KEY))[2:-1] + ("00" * (BLOCK_SIZE - len(KEY)))
		
# XORing of pads with keys
o_key_pad = hex(OPAD ^ int(KEY_PRIME, 16))[2:]
i_key_pad = hex(IPAD ^ int(KEY_PRIME, 16))[2:]

# Padding the XOR results to multiple of block size
if len(i_key_pad) < BLOCK_SIZE_BITS:
	i_key_pad += "0"*(BLOCK_SIZE_BITS-len(i_key_pad))	
if len(o_key_pad) < BLOCK_SIZE_BITS:
	o_key_pad += "0"*(BLOCK_SIZE_BITS-len(o_key_pad))

# Performing hashing
inner_hash_input = i_key_pad + str(binascii.hexlify(MESSAGE))[2:-1]
inner_hash = md5(inner_hash_input, True).hexdigest()
outer_hash_input = o_key_pad + inner_hash
outer_hash = md5(outer_hash_input, True).hexdigest()

#Resulting HMAC
print(outer_hash)
