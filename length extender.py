#length_extender.py
#An implementation of the length extension attack against MD5 encryption

from pymd5 import md5

def pad_message(message_length):
	bit_length = int(message_length) * 8
	
	# Begin padding
	padding = "1"
	bit_length += 1
	while (bit_length % 512 != 448):
		padding = padding+"0"
		bit_length += 1

	# Appending length represented as 64 bit string
	length_padding = str(bin(message_length))[2:]
	while len(length_padding) < 64:
		length_padding += "0"
	padding += length_padding

	return str(hex(int(padding, 2)))[2:-1].decode("hex")
	
def length_extension(input_length, input_hash, appended_string):
	
	# This creates the MD5 hash starting from the final state of the 
	# original message hash

	bits_processed = (input_length + len(pad_message(input_length))) * 8
	new_hash = md5(string = appended_string,
			   	   state = input_hash.decode("hex"),
			       count = bits_processed
	)	
		
	return new_hash.hexdigest()
	
# Adversary doesn't know this
secret = "EECS_475_"

# Adversarys real user_input
user_input = "MalloryF"

# What the adversary wants to append to the original hash
adversary_extension = "A"
original_hash = md5(secret + user_input).hexdigest()

legit_hash = md5(secret + user_input + pad_message(len(secret + user_input)) + adversary_extension).hexdigest()
print "Legitimate Message Hash:" + legit_hash

# Note how the length extension function is never actually given the secret
# but it still manages to produce the correct hash
secret_length = len(secret)
print "Adversary Hash: " + length_extension(secret_length + len(user_input), original_hash, adversary_extension)

string_created = secret + user_input + pad_message(len(secret)) + adversary_extension
print "String created (ASCII): " + string_created
print "String created (Hex): " + string_created.encode("hex")
