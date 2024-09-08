import random
import utime

class DiscreteLogDisjunctionInteractive():
    """
    Implementation of a Zero-Knowledge Proof protocol for discrete logarithm equality.
    """

    def __init__(self, g: int, h: int,xG: int, xH: int, p: int, x: int = None):
        self._p = p
        self._g = g
        self._xG = xG
        self._h = h
        self._xH = xH
        self._x = x
        # Use cryptographically secure random generator
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

    def commitments(self):
        """
        Generates commitments for the protocol.
        """
        self._v = self.randint(0, self._p - 1)
        self._vG = pow(self._g, self._v, self._p)
        self._vH = pow(self._h, self._v, self._p)
        return self._vG, self._vH

    def challenge(self) -> int:
        """
        Generates a random challenge value.
        """
        self._c = self.randint(1, self._p - 1)
        return self._c

    def response(self, c: int) -> int:
        """
        Calculates the response based on the challenge.
        """
        self._r = (self._v - self._x * c) % (self._p - 1)
        return self._r

    def verify(self, c: int, r: int, vG: int, vH: int) -> bool:
        """
        Verifies the ZKP given the challenge, response, and commitments.
        """
        # Calculate the verification values using the prover's response
        v1 = pow(self._g, r, self._p) * pow(self._xG, c, self._p) % self._p
        v2 = pow(self._h, r, self._p) * pow(self._xH, c, self._p) % self._p

        # Check if the recalculated commitments match the original commitments
        assert v1 == vG
        assert v2 == vH

if __name__ == "__main__":
    
    g = 2
    h = 3
    x = 5
    p = 1019
        
    P = pow(g, x, p)
    Q = pow(h, x, p)
    
    client_a = DiscreteLogDisjunctionInteractive(g, h, P, Q, p, x)
    client_b = DiscreteLogDisjunctionInteractive(g, h, P, Q, p)
    
    start_response = utime.ticks_us()
    t1, t2 = client_a.commitments()
    c = client_b.challenge()
    s = client_a.response(c)
    end_response = utime.ticks_us()
    client_b.verify(c, s, t1, t2)
    
    end_verify = utime.ticks_us()

    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )