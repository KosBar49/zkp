import hashlib
import random
import utime

class DiscreteLogDisjunction():

    def __init__(self, g, h, P, Q, p, x=None):
        """
        Initialize the protocol parameters.
        :param g, h: Generators of the group.
        :param P, Q: Public values such that P = g^a and Q = h^b.
        :param p: Prime modulus.
        :param x: Secret value.
        """
        self._g = g
        self._h = h
        self._P = P
        self._Q = Q
        self._p = p
        self._x = x
        self._random = random
        
    def randint(self, a, b):
        if a >= 0 and b >= 0:
            if b - a < 2**31:
                return random.randint(a, b)
            else:
                high = (b - a) // (2**31 - 1) + 1
                low = (b - a) % (2**31 - 1)
                return a + high * random.randint(0, (2**31 - 1) - 1) + random.randint(0, low)
        else:
            raise ValueError("Both a and b must be non-negative")
        
    def _hash(self, itmes):
        s_ = ''
        h = hashlib.sha256()
        for item in itmes:      
            s_ += str(item)
        h.update(s_.encode())
        return int(h.digest().hex(), 16)

    def response(self):
        r1 = self.randint(0, self._p - 1)
        c2 = self.randint(0, self._p - 1)
        s2 = self.randint(0, self._p - 1)

        t1 = pow(self._g, r1, self._p)
        
        p1 = pow(self._h, s2, self._p)
        
        p2 = 1 / (pow(self._Q, c2, self._p))
        
        t2 = (p1 * p2) % self._p
        
        c = self._hash([self._g, self._h, self._P, self._Q, t1, t2]) % self._p

        c1 = (c - c2) % self._p

        s1 = (r1 + c1 * self._x) % (self._p - 1)

        return (t1, c1, s1), (t2, c2, s2)

    def verify(self, g, h, P, Q, t1c1s1, t2c2s2):
        (t1, c1, s1) = t1c1s1
        (t2, c2, s2) = t2c2s2
        
        c = self._hash([g, h, P, Q, t1, t2]) % self._p

        assert (c == (c1 + c2) % self._p)

        lhs1 = pow(g, s1, self._p)
        rhs1 = (t1 * pow(P, c1, self._p)) % self._p

        lhs2 = pow(h, s2, self._p)
        rhs2 = int(t2 * pow(Q, c2, self._p)) % self._p

        assert lhs1 == rhs1 and lhs2 == rhs2
        
    
if __name__ == "__main__":
    
    g = 2
    h = 3
    x = 5
    y = 7
    p = 1019
        
    P = pow(g, x, p)
    Q = pow(h, y, p)
    
    client_a = DiscreteLogDisjunction(g, h, P, Q, p, x)
    client_b = DiscreteLogDisjunction(g, h, P, Q, p)
    
    start_response = utime.ticks_us()
    t1c1s1, t2c2s2 = client_a.response()
    end_response = utime.ticks_us()
    client_b.verify(g, h, P, Q, t1c1s1, t2c2s2)
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )