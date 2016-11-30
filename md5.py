# -*- coding: utf-8 -*-
"""MD5 Implementation

This is an implementation of the MD5 algorithm.
This implementation is intended for academic use only.

Authors:
	Brandon Mendrick
	Neil Orans

"""

from math import floor, sin

class MD5:
	"""MD5 class used to calculate MD5 hash values."""

	# Number of 32 bit strings
	bit32 = 2**32

	# Number of 64 bit strings
	bit64 = 2**64

	# Amount of shift per round
	shift = [
		7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
		5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
		4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
		6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
	]

	# Constants adding during each round
	constant = [None] * 64
	for i in range(0, 64, 1):
		constant[i] = floor(bit32 * abs(sin(i + 1)))

	def __init__(self, message):
		# Initial word values
		self.A = 0x67452301
		self.B = 0xefcdab89
		self.C = 0x98badcfe
		self.D = 0x10325476

		self.parse(message)

		self.calculate()

		self.output()

		return

	def _rotate(self, target, num):
		"""Left rotate function defined in MD5."""
		return (target << num) | (target >> (32 - num))

	def calculate(self):
		"""Compute the A, B, C, D values for MD5."""
		# For each 512-bit block
		for j in range(1, self.numBlocks + 1):
			currentBlock = self.parsedMessage[j]

			currentA = self.A
			currentB = self.B
			currentC = self.C
			currentD = self.D
			function = None
			position = None

			# Main loop
			for i in range(64):
				# Setting the function and position variables for this round
				if 0 <= i <= 15:
					function = (currentB & currentC) | ((~currentB) & currentD)
					position = i

				elif 16 <= i <= 31:
					function = (currentD & currentB) | ((~currentD) & currentC)
					position = ((5 * i) + 1) % 16

				elif 32 <= i <= 47:
					function = currentB ^ currentC ^ currentD
					position = ((3 * i) + 5) % 16

				elif 48 <= i <= 63:
					function = currentC ^ (currentB | (~currentD))
					position = (7 * i) % 16

				else:
					print("Something went horribly wrong")
					return

				# Setting the A, B, C, D variables after the round
				tempD = currentD
				currentD = currentC
				currentC = currentB

				# Calculating B based on MD5 algorithm
				rotateTarget = (currentA + function + MD5.constant[i] + currentBlock[position]) % MD5.bit32
				currentB = (currentB + self._rotate(rotateTarget, MD5.shift[i])) % MD5.bit32
				
				currentA = tempD

			# Adding the results of the round to the overall A, B, C, D variables
			self.A = (self.A + currentA) % MD5.bit32
			self.B = (self.B + currentB) % MD5.bit32
			self.C = (self.C + currentC) % MD5.bit32
			self.D = (self.D + currentD) % MD5.bit32

	def parse(self, message):
		"""Parse message into 512-bit chunks and pad appropriately."""
		# Message length in bits mod 2**64 for last 64-bits of padding
		self.msgLen = (len(message.encode('utf-8')) * 8) % MD5.bit64

		# Creating counter for number of blocks
		self.numBlocks = 0

		# Creating container for blocks
		self.parsedMessage = {}

		# Creating array of integers from the message
		msgInt = [ord(x) for x in message]

		# Counter for the number of bits processed
		bitsProcessed = 0

		currentBlock = 0b0
		while len(msgInt) > 0:		#FIXME should support empty messages. Not sure what happens....
			currentCharacter = msgInt.pop(0)

			# Appending the character to the current block
			currentBlock = currentBlock << 8
			currentBlock = currentBlock | currentCharacter

			# Bookkeeping
			bitsProcessed += 8

			if bitsProcessed % 512 == 0:
				self.numBlocks += 1
				self.parsedMessage[self.numBlocks] = currentBlock

				bitsProcessed = 0
				currentBlock = 0b0

		# Checking if we ended at the end of a block
		if bitsProcessed % 512 == 0:
			self.numBlocks += 1
			self.parsedMessage[self.numBlocks] = currentBlock

			bitsProcessed = 0
			currentBlock = 0b0

		# Adding padding
		if bitsProcessed >= 448:
			return #FIXME
			# probably needs to be an if else case as the padding for this
			# and the "standard" case are rather different.

		# Amount of padding needed to get to 448 bits in the last chunk
		paddingLen = 448 - bitsProcessed

		# paddingLen - 1 (for 1 bit) + 64 (for length at end)
		padding = (0b1 << (paddingLen - 1 + 64)) | self.msgLen

		# Total amount of shift
		totalShift = paddingLen + 64

		# Calculating the final block and adding it to the data structure
		currentBlock = (currentBlock << totalShift) | padding
		self.numBlocks += 1
		self.parsedMessage[self.numBlocks] = currentBlock

		# Breaking parsedMessage into 32-bit words
		for i in range(1, self.numBlocks + 1):
			block = str(hex(self.parsedMessage[i])).split('x')[1]
			parsedBlock = []

			for _ in range(16):
				parsedBlock = [int(block[-8:], 16)] + parsedBlock
				block = block[:-8]

			self.parsedMessage[i] = parsedBlock

	def output(self):
		"""Outputs the results of the MD5 hash."""
		outA = str(hex(self.A)).split('x')[1]
		outB = str(hex(self.B)).split('x')[1]
		outC = str(hex(self.C)).split('x')[1]
		outD = str(hex(self.D)).split('x')[1]

		output = outA + outB + outC + outD

		print(output)
		print(hex(self.A), hex(self.B), hex(self.C), hex(self.D))

def main():
	"""Main function if the program is executed from the command line."""
	tmp = MD5("a")

if __name__ == "__main__":
	main()