import random
import hashlib
import utime

class PedersenCommitment():
    """
    Non-interactive Pedersen Commitment in a cyclic group of prime order.
    """

    def __init__(self, g: int, h: int, p: int, x: int = None, y: int = None) -> None:
        """
        Initialize the commitment scheme with public parameters and optionally secret values.
        :param p: The prime order of the cyclic group.
        :param g: The generator of the group.
        :param h: Another generator of the group, where no one knows the discrete log of h with respect to g.
        :param x: The secret value associated with g.
        :param y: The secret value associated with h.
        """
        self.g = g
        self.h = h
        self.x = x
        self.y = y
        self.p = p
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

    def response(self, P: int) -> tuple:
        """
        Generate a commitment and response for the given value P.
        :param P: The public point (or value) associated with the secrets x and y.
        :return: A tuple of the commitment (t), and responses (s1, s2).
        """
        r1 = self._random.randint(1, self.p - 1)
        r2 = self._random.randint(1, self.p - 1)

        # Commitment
        t = (pow(self.g, r1, self.p) * pow(self.h, r2, self.p)) % self.p
        c = self._hash([self.g, self.h, P, t]) % self.p
        
        # Responses
        s1 = (r1 + c * self.x) % (self.p - 1)
        s2 = (r2 + c * self.y) % (self.p - 1)

        return t, s1, s2

    def verify(self, g: int, h: int, P: int, t: int, s1: int, s2: int) -> bool:
        """
        Verify the validity of a given commitment and responses.
        :param g, h: The generators.
        :param P: The public point/value.
        :param t: The commitment.
        :param s1, s2: The responses.
        :return: True if the commitment and responses are valid, False otherwise.
        """
        # Calculate left hand side (LHS) of the verification equation
        lhs = (pow(g, s1, self.p) * pow(h, s2, self.p)) % self.p
        c = self._hash([g, h, P, t]) % self.p
        # Calculate right hand side (RHS) of the verification equation
        rhs = (t * pow(P, c, self.p)) % self.p
  
        assert lhs == rhs
        
        
if __name__ == "__main__":
    
    g = 2
    h = 3
    x = 5
    y = 7
    p = 1019
    
    P = (pow(g, x, p) * pow(h, y, p)) % p
    
    client_a = PedersenCommitment(g, h, p, x, y)
    client_b = PedersenCommitment(g, h, p)
    
    start_response = utime.ticks_us()

    (t, s1, s2) = client_a.response(P)
    
    end_response = utime.ticks_us()

    client_b.verify(g, h, P, t, s1, s2)
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )