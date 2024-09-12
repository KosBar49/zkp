import random
import hashlib
import utime
from ecc import randint

def extended_gcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def mod_inv(a, mod):
    gcd, x, _ = extended_gcd(a, mod)
    if gcd != 1:
        raise ValueError(f"No modular inverse for {a} mod {mod}")
    return x % mod

def mod_exp(base, exp, mod):
    if exp < 0:
        # Compute the modular inverse of base^(-exp)
        base = mod_inv(base, mod)
        exp = -exp
    
    result = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:  # If exp is odd, multiply base with result
            result = (result * base) % mod
        exp = exp >> 1  # exp = exp // 2
        base = (base * base) % mod  # Change base to base^2
    return result

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
        r1 = randint(self.p - 1)
        r2 = randint(self.p - 1)

        # Commitment
        t = (mod_exp(self.g, r1, self.p) * mod_exp(self.h, r2, self.p)) % self.p
        c = self._hash([self.g, self.h, P, t]) % self.p
        
        # Responses
        s1 = (r1 + c * self.x) #% (self.p - 1)
        s2 = (r2 + c * self.y) #% (self.p - 1)

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
        lhs = (mod_exp(g, s1, self.p) * mod_exp(h, s2, self.p)) % self.p
        c = self._hash([g, h, P, t]) % self.p
        # Calculate right hand side (RHS) of the verification equation
        rhs = (t * mod_exp(P, c, self.p)) % self.p
  
        assert lhs == rhs
        
        
if __name__ == "__main__":
    
    g = 5
    h = 3
    x = 762255500
    y = 215569921

    #p = 57896044618658097711785492504343953926634992332820282019728792003956564819968
    p = 170154366828665079503315635359566390626153860097410117673698414542663355444709893966571750073322692712277666971313348160841835991041384679700511912064982526249529596585220499141442747333138443745082395711957231040341599508490720584345044145678716964326909852653412051765274781142172235546768485104821112642811
    P = (mod_exp(g, x, p) * mod_exp(h, y, p)) % p
    
    client_a = PedersenCommitment(g, h, p, x, y)
    client_b = PedersenCommitment(g, h, p)
    
    start_response = utime.ticks_us()

    (t, s1, s2) = client_a.response(P)
    
    end_response = utime.ticks_us()

    client_b.verify(g, h, P, t, s1, s2)
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )