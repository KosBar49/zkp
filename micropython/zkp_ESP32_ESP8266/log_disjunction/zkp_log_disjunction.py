import random
import utime

class DiscreteLogDisjunctionInteractive():
    def __init__(self, g, h, P, Q, p, x=None):
        """
        Initializes the ZKP instance for a disjunction of discrete logs.

        :param g: Base g of the discrete logarithm problem.
        :param h: Base h, used in the disjunction.
        :param P: Public value g^a mod p.
        :param Q: Public value h^b mod p.
        :param p: Prime modulus.
        :param x: The secret (either a or b).
        :param knows: Indicates whether the prover knows 'a' or 'b'.
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

    def challenge(self):
        """
        Generates a random challenge.

        :return: A random challenge c.
        """
        self._c = self._random.randint(1, self._p - 1)
        return self._c

    def commitment(self):
        """
        Generate commitment values for a cryptographic protocol.

        This function does not take any parameters and returns a tuple of two integers representing the commitment values.
        """
        self._r1 = self.randint(0, self._p - 1)
        self._s2 = self.randint(0, self._p - 1)
        self._c2 = self.randint(0, self._p - 1)
        t1 = pow(self._g, self._r1, self._p)

        
        p1 = pow(self._h, self._s2, self._p)
        p2 = 1 / (pow(self._Q, self._c2, self._p))  #pow(self._Q, -self._c2, self._p)
        
        
        print(f"p1: {p1}, p2: {p2}")
        t2 = (p1 * p2) % self._p
        return (t1, t2)
        
    def response(self, c):
        """
        Calculate the response to a given challenge. 

        Args:
            c: The challenge value.

        Returns:
            Tuple of two tuples:
                - Tuple of (c1, s1) values calculated from the challenge.
                - Tuple of (self._c2, self._s2) values.

        """
        c1 = (c - self._c2) % self._p
        s1 = (self._r1 + c1 * self._x) % (self._p - 1)

        return (c1, s1), (self._c2, self._s2)

    def verify(self, g, h, P, Q, c1s1, c2s2, t1, t2):
        """
        Verifies the response against the original challenge.

        :param g, h, P, Q: Public parameters.
        :param t1c1s1: The first tuple of proof components.
        :param t2c2s2: The second tuple of proof components.
        """
        (c1, s1) = c1s1
        (c2, s2) = c2s2

        # Ensure the total challenge c equals the sum of c1 and c2.
        assert (self._c == (c1 + c2) % self._p), "Challenge mismatch"

        # Verify the first proof.
        lhs1 = pow(g, s1, self._p)
        rhs1 = (t1 * pow(P, c1, self._p)) % self._p

        # Verify the second proof.
        lhs2 = pow(h, s2, self._p)
        rhs2 = (t2 * pow(Q, c2, self._p)) % self._p
        print(f"lhs1: {lhs1}, lhs2: {lhs2}, rhs1: {rhs1}, rhs2: {rhs2}")
        assert lhs2 == rhs2 and lhs1 == rhs1
        
    
if __name__ == "__main__":
    
    g = 2
    h = 3
    x = 5
    y = 7
    p = 1019
        
    P = pow(g, x, p)
    Q = pow(h, y, p)
    
    print(Q)
    
    client_a = DiscreteLogDisjunctionInteractive(g, h, P, Q, p, x)
    client_b = DiscreteLogDisjunctionInteractive(g, h, P, Q, p)
    
    start_response = utime.ticks_us()
    (t1, t2) = client_a.commitment()
    c = client_b.challenge()
    c1s1, c2s2 = client_a.response(c)
    end_response = utime.ticks_us()
    
    client_b.verify(g, h, P, Q, c1s1, c2s2, t1, t2)   
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )