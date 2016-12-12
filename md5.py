# -*- coding: utf-8 -*-
"""MD5 Implementation

This is an implementation of the MD5 algorithm intended for academic use
only. Implementation is based off of the existing Python2 MD5 module and 
the psuedocode provide on Wikipedia. 

RFC 1321 was also used as a reference.

Authors:
	Brandon Mendrick
	Neil Orans

"""

from math import floor, sin
import sys

class MD5:
	def __init__(self, message, hex_=False):
		## Constants
		self.bit32 = 2**32
		self.bit64 = 2**64

		## Initial MD5 values
		self._A = 0x67452301
		self._B = 0xEFCDAB89
		self._C = 0x98BADCFE
		self._D = 0x10325476

		self.shift = []
		self.shift += [7, 12, 17, 22] * 4
		self.shift += [5,  9, 14, 20] * 4
		self.shift += [4, 11, 16, 23] * 4
		self.shift += [6, 10, 15, 21] * 4
		
		self.constant = [None] * 64
		for i in range(0, 64, 1):
			self.constant[i] = int(floor(self.bit32 * abs(sin(i + 1))))

		## Hashing given string
		self.hex_ = hex_
		self.msg = message
		if not self.msg:
			self.msg = ""

		self._hash()

	## Public methods

	def digest(self):
		"""Returns a byte string of the hash value."""
		parts = [self._resA, self._resB, self._resC, self._resD]
		result = b''

		for part in parts:
			tmp = str(bin(part))[2::]
			tmp = '0' * (32 - len(tmp)) + tmp
			tmp = self._split(tmp, 8)[::-1]

			for byte in tmp:
				result += bytes([int(byte, 2)])

		return result

	def hexdigest(self):
		"""Returns a hex string of the hash value."""
		result = ""
		for byte in self.digest():
			result += "{:02x}".format(byte)

		return result

	def update(self, message):
		"""Appends the input message to the current message.

		After the appending, it updates the hash value for future calls
		to (hex)digest.

		"""
		self.msg += message

		self._hash()

	## Private methods

	def _addMod32(self, *args):
		"""Adds all arguments modulo 2**32."""
		result = 0
		for arg in args:
			result += arg

		return (result % self.bit32)

	def _createWords(self, chunk):
		"""Breaks the input into 16 32-bit chunks.

		input: 512-bit string
		output: array[16] 32-bit numbers

		Additionally, swaps order to be Little Endian.

		"""
		wordArray = [None] * 16
		wordChunks = self._split(chunk, 32)
		currentWord = 0

		for wordChunk in wordChunks:
			bytes_ = self._split(wordChunk, 8)
			chunk = ""

			# reversing the order of the bytes
			for byte in bytes_:
				chunk = byte + chunk

			wordArray[currentWord] = int(chunk, 2)
			currentWord += 1

		return wordArray

	def _hash(self):
		"""Running the MD5 hashing algorithm."""
		## Making life easier and more readable
		A, B, C, D = self._A, self._B, self._C, self._D
		F, G, H, I = self._F, self._G, self._H, self._I

		# message to bitstring, padded, and split into 512-bit chunks
		if self.hex_:
			self.parsedMsg = self._split(self._pad(self._hexToBinString(self.msg)), 512)
		else:
			self.parsedMsg = self._split(self._pad(self._toBinString(self.msg)), 512)

		for chunk in self.parsedMsg:
			# Breaking the chunk into 16 32-bit words
			words = self._createWords(chunk)

			# bookkeeping
			a, b, c, d = A, B, C, D
			func, pos = None, None
			
			# Main loop
			for i in range(64):
				# Setting the func and pos variables for this round
				if 0 <= i <= 15:
					func = F
					pos = i

				elif 16 <= i <= 31:
					func = G
					pos = ((5 * i) + 1) % 16

				elif 32 <= i <= 47:
					func = H
					pos = ((3 * i) + 5) % 16

				elif 48 <= i <= 63:
					func = I
					pos = (7 * i) % 16

				else:
					print("Something went horribly wrong")
					return

				# Computing the value of B (only variable that is changed in a round)
				tmpB = self._round(func, a, b, c, d, self.constant[i], words[pos], self.shift[i])

				# Moving A, B, C, D to their new homes
				tmpD = d
				d = c
				c = b
				b = tmpB
				a = tmpD

			# Finishing processing of a chunk
			A = self._addMod32(A, a)
			B = self._addMod32(B, b)
			C = self._addMod32(C, c)
			D = self._addMod32(D, d)

		# assigning results to class variables for (hex)digest use
		self._resA, self._resB, self._resC, self._resD = A, B, C, D

	def _hexToBinString(self, hexString):
		result = str(bin(int(hexString, 16))[2:])

		while (len(result) % 8 != 0):
			result = '0' + result

		return result

	def _pad(self, bitString):
		"""Pads the message according to MD5.

		Pad the message with a 1 followed by 0s until the length is 
		448 mod 512. Remaining 64 bits encode the length of the original
		message.

		"""
		msgLen = len(bitString)

		## padding with zeros
		bitString += '1'
		while (len(bitString) % 512) != 448:
			bitString += '0'

		## adding the 64 bit message length encoding
		binLen = str(bin(msgLen))[2::]

		# making sure binLen is a byte length
		while (len(binLen) % 8) != 0:
			binLen = '0' + binLen

		# checking if the length is over 64 bits
		#TODO pretty sure this doesn't work...
		if len(binLen) > 64:
			bitString += '0' + '1' * 63
			return bitString

		# padding in this weird way to account for later shifts
		padding = '0' * (64 - len(binLen))
		padding += binLen
		padding = self._split(padding, 32)
		padding = ''.join(self._split(padding[1], 8)[::-1]) + ''.join(self._split(padding[0], 8)[::-1])

		bitString += padding

		return bitString

	def _split(self, bitString, size):
		"""Return an array of the bitString broken into size chunks."""
		return [ bitString[i:(i + size)] for i in range(0, len(bitString), size) ]

	def _toBinString(self, message):
		"""Convert string to bitstring."""
		result = ""
		for letter in message.encode("utf-8"):
			result += "{:08b}".format(letter)

		return result

	## MD5 functions

	def _F(self, x, y, z):
		"""Compute (x and y) or ((not x) and z)."""
		return (x & y) | ((~x) & z)

	def _G(self, x, y, z):
		"""Compute (x and z) or (y and (not z))."""
		return (x & z) | (y & (~z))

	def _H(self, x, y, z):
		"""Compute x xor y xor z."""
		return x ^ y ^ z

	def _I(self, x, y, z):
		"""Compute y xor (x or (not z))."""
		return y ^ (x | (~z))

	def _round(self, func, a, b, c, d, constant, chunk, shift):
		"""Compute a round of the MD5 algorithm."""
		result = self._addMod32(a, func(b, c, d), constant, chunk)
		result = self._rotateLeft(result, shift)
		result = result % self.bit32
		result = self._addMod32(result, b)

		return result

	def _rotateLeft(self, bitString, shift):
		"""Compute the left rotation of the bitString shift places."""
		return (bitString << shift) | (bitString >> (32 - shift))

## Public module interface
def new(string, hex_=False):
	"""Create new instance of MD5 class."""
	return MD5(string, hex_)

def md5(string, hex_=False):
	"""Create new instance of MD5 class."""
	return MD5(string, hex_)

def main():
	"""Main function for testing purposes."""
	# obj = md5("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
	# obj = md5("abc")

	obj = md5("48656c6c6f", True)
	# obj = md5("Hello", False)

	# string = ""
	# for i in range(1000):
	# 	string += "1234567890"
	# string += "123"
	# obj = md5(string)

	print(obj.hexdigest())

"""Calling main for testing purposes."""
if __name__ == "__main__":
	main()