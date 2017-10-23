"""
# Author: Joshua Church
# Assignment: RSA / El Gamal
#
# Objective: Write Python functions for the following:
# - key generation
# - encryption
# - decryption
# - signing 
# - verification
#
# For RSA, the following values should be chosen:
# - p -> 7919
# - q -> 7589
# 
# Must find the smallest possible encryption component.
# 
# For El Gamal, the following values should be chosen: 
# - p -> 3000273817
# - g -> 23
#
"""

import random
import hashlib
import binascii
from fractions import gcd

class RSA:
	def __init__(self, p, q, P):
		self.p = p
		self.q = q
		self.P = P # Padded reversible message 
		#self.p = 1009
		#self.q = 503

	def key_generation(self):
		print("\n===== KEY GENERATION PHASE =====")

		# Compute n = pq, where
		# n is the modulus for the public key and the private keys
		self.n = self.p * self.q

		# Compute Euler Totient (Euler Phi)
		# Since p & q are prime, then totient is (p-1)*(q-1)
		self.totient = (self.p - 1)*(self.q - 1)

		# Choose an integer 'e' such that 1 < e < totient(n), 
		# and e is coprime to totient(n) (share no common factors other than 1)
		# --> gcd(e, totient(n)) = 1

		# e is released as the public key exponent
		self.e = 1
		while True:
			self.e += 1
			
			if (gcd(self.e, self.totient) == 1):
				break

		print(" --> Smallest encryption exponent (e): " + str(self.e))
		# Compute 'd' to satisfy the congruence relation d*e mod totient(n) == 1
		# d is kept as the private key exponent
		print(" --> Calculating private key (d). One moment...")
		self.d = 0
		while True:
			self.d += 1

			if ((self.d * self.e) % self.totient == 1):
				break

		print(" --> Private key (d) found: " + str(self.d))
	# To send a secret P to Alice, Bob computes C = P^e mod n
	# C represents ciphertext
	def encryption(self):
		print("\n===== ENCRYPTION PHASE =====")
		print(" --> Plaintext before encryption: " + str(self.P))
		self.C = pow(self.P, self.e, self.n)
		print(" --> Ciphertext after encryption: " + str(self.C))

	# Alice decrypts C as P = C^d mod n
	# This works because 
	# C^d = (P^e)^d = P^(ed) = P^(k*totient(n)+1) = P mod n
	# As d and e are multiplicative inverses mod totient(n)
	def decryption(self):
		print("\n===== DECRYPTION PHASE =====")
		print(" --> Ciphertext before decryption: " + str(self.C))
		self.P = pow(self.C, self.d, self.n)
		print(" --> Plaintext after decryption: " + str(self.P))

	def signing(self):
		print("\n===== SIGNING PHASE =====")
		print(" --> Message before MD5 hash: " + str(self.P))
		self.M = hashlib.md5()
		self.M.update(str(self.p).encode("utf-8"))
		self.M = self.M.hexdigest()
		self.M = int(self.M, 16)
		self.M = self.M%10000000
		print(" --> Message aftering MD5 hash (with %10000000 to keep it under the d value): " + str(self.M))
		self.S = pow(self.M, self.d, self.n)
		print(" --> Signed hash value: (S): " + str(self.S))

	def verification(self):
		print("\n===== VERIFICATION PHASE =====")
		self.verify = pow(self.S, self.e, self.n)
		print(" --> Expected value for verification: " + str(self.M))
		print(" --> Received verification value: " + str(self.verify))

		if (self.verify == self.M):
			print(" --> VALID MESSAGE!")
		else:
			print("--> INVALID MESSAGE!")

###########################################################################################

# The following extended Euclidien function was found at:
# http://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

# The following modular inverse function was found at: 
# http://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        return False
    else:
        return x % m

class ElGamal:
	def __init__(self, p, g, P):
		self.p = p
		self.g = g
		self.P = P
		self.phi = self.p - 1

	def key_generation(self): 
		print("\n===== KEY GENERATION PHASE =====")
		# Choose random private key 
		self.a = random.randint(2, self.p - 1)
		print(" --> Private key chosen: " + str(self.a))

		# Set public key 
		self.pub_key = pow(self.g, self.a, self.p)
		print(" --> Public key: " + str(self.pub_key))

	def encryption(self):
		print("\n===== ENCRYPTION PHASE =====")
		print(" --> (P) before encryption: " + str(self.P))
		self.k = random.randint(1, self.p - 1)
		print(" --> (k) value is: " + str(self.k))

		self.pub_key_2 = pow(self.pub_key, self.k, self.p)
		self.C = pow((self.P*self.pub_key_2), 1, self.p)
		print(" --> (C) value is: " + str(self.C))

		self.mu = pow(self.g, self.k, self.p)
		print(" --> (mu) value is: " + str(self.mu))

	def decryption(self):
		print("\n===== DECRYPTION PHASE =====")
		self.x = pow(self.mu, self.a, self.p)
		print(" --> (mu)^a mod p: " + str(self.x))

		try: 
			self.mod_inverse = modinv(self.x, self.p)
			print(" --> Modular Inverse: " + str(self.mod_inverse))
			print(" --> (P) before decryption: " + str(self.P))
			self.P = pow(C*mod_inverse, 1, self.p)
			print(" --> (P) after decryption: " + str(self.P))

		except:
			print("ERROR: Unable to find a modular inverse.")

	def md5_hash(self):
		print("\n===== HASH PHASE =====")
		print(" --> Message before hashing: " + str(self.P))
		self.M = hashlib.md5()
		self.M.update(str(self.P).encode("utf-8"))
		self.M = self.M.hexdigest()
		self.M = int(self.M, 16) 
		self.M = self.M%10000000 
		print(" --> Message after MD5 hash: " + str(self.M))

	def signing(self):
		print("\n===== SIGNING PHASE =====")
		self.k = random.randint(3, self.p - 1)
		print(" --> (k) value chosen: " + str(self.k))

		self.mod_inverse = modinv(self.k, self.p - 1)
		while self.mod_inverse == False:
			print("\t | ERROR: This k value does not have an inverse.")
			self.k = random.randint(3, self.p -1)
			print(" --> Trying (k) value of: " + str(self.k))
			self.mod_inverse = modinv(self.k, self.p - 1)

		print(" --> (k) value: " + str(self.k) + " | Inverse: " + str(self.mod_inverse))

		self.mu = pow(self.g, self.k, self.p)
		print(" --> (mu) value: " + str(self.mu))

		self.S = (self.M - self.a*self.mu)
		self.S = pow(self.S*self.mod_inverse, 1, self.p - 1)
		print(" --> (S) value: " + str(self.S))

	# x^y mod p = (x^(y mod phi) mod p) mod p
	def verification(self):
		print("\n===== VERIFICATION PHASE =====")
		self.r0 = pow(self.pub_key, 1, self.p)
		self.r1 = pow(self.mu, 1, self.phi)
		self.r2 = pow(self.r0, self.r1, self.p)

		self.t0 = pow(self.mu, 1, self.p)
		self.t1 = pow(self.S, 1, self.phi)
		self.t2 = pow(self.t0, self.t1, self.p)

		# The value we actually received
		self.final = pow(self.r2 * self.t2, 1, self.p)

		# The value that is expected for verification purposes
		self.expected = pow(self.g, self.M, self.p)

		print(" --> Expected value: " + str(self.expected))
		print(" --> Calculated value: " + str(self.final))

		# Compare the results
		if self.final == self.expected:
			print(" --> VALID MESSAGE!")
		else:
			print("--> INVALID MESSAGE!")


	
def run_rsa():
	print("\n============ RSA ==============")
	#p = int(input("Please enter a p-value: (the expected value is 7919) --> "))
	#q = int(input("Please enter a q-value: (the expected value is 7589) --> "))
	p = 7919
	q = 7589
	P = 423621
	print("VALUES: (p) --> " + str(p) + " | (q) --> " + str(q) + " | Padded Secret Message (P) --> " + str(P))

	r = RSA(p, q, P)
	r.key_generation()
	r.encryption()
	r.decryption()
	r.signing()
	r.verification()

def run_el_gamal():
	print("\n============ EL GAMAL ==============")
	p = 3000273817 	# Large Prime
	g = 23			# Different Large Prime
	P = 423621		# Secret message to be sent
	print("VALUES: (p) --> " + str(p) + " | (g) --> " + str(g) + " | Padded Secret Message (P) --> " + str(P))
	
	e = ElGamal(p, g, P)
	e.key_generation()
	e.encryption()
	e.decryption()
	e.md5_hash()
	e.signing()
	e.verification()


if __name__ == "__main__":
	run_rsa()
	run_el_gamal()


