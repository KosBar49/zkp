import random
import hashlib

class PedersenCommitmentsEqualMessagesInteractive:
    def __init__(self, p, g, h, x=None, y=None, z=None):
        self._p = p  # Large prime
        self._g = g  # Generator g
        self._h = h  # Generator h
        if x and y and z:
            self._x = x
            self._y = y
            self._z = z
            
    def challenge(self):
        return random.randint(1, self._p - 1)

    def generate_commitments(self):
        self.r1 = random.randint(1, self._p - 1)
        self.r2 = random.randint(1, self._p - 1)
        self.r3 = random.randint(1, self._p - 1)
        
        # Generate temporary commitments
        t1 = (pow(self._g, self.r1, self._p) * pow(self._h, self.r2, self._p)) % self._p
        t2 = (pow(self._g, self.r1, self._p) * pow(self._h, self.r3, self._p)) % self._p
        
        return t1, t2

    def response(self, c):
        s1 = (self.r1 + c * self._x) % (self._p - 1)
        s2 = (self.r2 + c * self._y) % (self._p - 1)
        s3 = (self.r3 + c * self._z) % (self._p - 1)
        
        return s1, s2, s3

    def verify(self, P, Q, t1, t2, c, s1, s2, s3):
        lhs1 = (pow(self._g, s1, self._p) * pow(self._h, s2, self._p)) % self._p
        lhs2 = (pow(self._g, s1, self._p) * pow(self._h, s3, self._p)) % self._p
        
        rhs1 = (t1 * pow(P, c, self._p)) % self._p
        rhs2 = (t2 * pow(Q, c, self._p)) % self._p

        assert lhs1 == rhs1 and lhs2 == rhs2

# Example usage
# Prover
p = 1019
g = 2 
h = 3     

x = 5
y = 7
z = 11
P = (pow(g, x, p) * pow(h, y, p))
Q = (pow(g, x, p) * pow(h, z, p)) 
    
protocol = PedersenCommitmentsEqualMessagesInteractive(p, g, h, x, y, z)
t1, t2 = protocol.generate_commitments()

# Verifier provides a challenge
c = random.randint(1, p - 1)

# Prover calculates responses
s1, s2, s3 = protocol.response(c)

# Verifier checks the proof
protocol.verify(P, Q, t1, t2, c, s1, s2, s3)
print("success")