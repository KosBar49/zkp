import hashlib
import random
import utime

class DiscreteLogEquality():
    """
    Implementation of a Zero-Knowledge Proof protocol for discrete logarithm equality.
    """

    def __init__(self, g: int, h: int,xG: int, xH: int, p: int, x: int = None):

        self._g = g
        self._P = P
        self._h = h
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
        """
        Calculates the response value based on the current object state.
        :return: The calculated response value.
        """
        self._v = self._random.randint(0, self._p - 1)
        self._vG = pow(self._g, self._v, self._p)
        self._vH = pow(self._h, self._v, self._p)
        
        self._c = self._hash([self._vG, self._vH, self._g, self._h])

        self._r = (self._v - self._x * self._c) % (self._p - 1)
        return self._c, self._r

    def verify(self, c, r):
        """
        Verify DLEQ proof on a certain condition.
        Args:
            c (int): The first parameter representing a value.
            r (int): The second parameter representing a value.
        Returns:
            None
        """
        v1 = (pow(self._g, r, self._p) * pow(self._P, c, self._p)) % self._p
        v2 = (pow(self._h, r, self._p) * pow(self._Q, c, self._p)) % self._p
        
        c1 = self._hash([v1, v2, self._g, self._h])
        assert c == c1

if __name__ == "__main__":
    
    g = 2
    h = 3
    x = 5
    p = 1019
        
    P = pow(g, x, p)
    Q = pow(h, x, p)
    
    client_a = DiscreteLogEquality(g, h, P, Q, p, x)
    client_b = DiscreteLogEquality(g, h, P, Q, p)
    
    start_response = utime.ticks_us()
    c, s = client_a.response()
    end_response = utime.ticks_us()
    client_b.verify(c, s)
    
    end_verify = utime.ticks_us()

    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )