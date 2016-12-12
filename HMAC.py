#An implementation of HMAC, using MD5 as the hashing algorithm.
#pymd5 comes from http://equi4.com/md5/pymd5.py

from pymd5 import md5

BLOCK_SIZE = 64 #MD5 input block size
BLOCK_SIZE_BITS = BLOCK_SIZE * 2 #Block size in bits (used zero-padding)
OPAD = int("5c" * 64, 16)
IPAD = int("36" * 64, 16)
KEY_PRIME = ""

KEY = "Hello"
MESSAGE = "World"

# If key is longer than block size, set key = hash(original key)
if len(KEY) > 64:
	KEY_PRIME = pymd5.md5(KEY)
	
# If key is shorter, pad with zeros to blocksize
if len(KEY) < 64:
	KEY_PRIME = KEY.encode("hex") + "00" * (BLOCK_SIZE - len(KEY))
	
# XORing of pads with keys
o_key_pad = hex(OPAD ^ int(KEY_PRIME, 16))[2:-1]
i_key_pad = hex(IPAD ^ int(KEY_PRIME, 16))[2:-1]

# Padding the XOR results to multiple of block size
if len(i_key_pad) < BLOCK_SIZE_BITS:
	i_key_pad = "0"*(BLOCK_SIZE_BITS-len(i_key_pad)) + i_key_pad	
if len(o_key_pad) < BLOCK_SIZE_BITS:
	o_key_pad = "0"*(BLOCK_SIZE_BITS-len(o_key_pad)) + o_key_pad

# Performing hashing
inner_hash_input = (i_key_pad).decode("hex") + MESSAGE
inner_hash = md5(inner_hash_input).hexdigest()
outer_hash_input = (o_key_pad + inner_hash).decode("hex")
outer_hash = md5(outer_hash_input).hexdigest()

#Resulting HMAC
print outer_hash
