import random 
import utime
from ecc import randint

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

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

class DiscreteLogConjunctionInteractive():

    def __init__(self, g, h, P, Q, p, a=None, b=None):
        """
        Initialize the protocol parameters.
        :param g, h: Generators of the group.
        :param P, Q: Public values such that P = g^a and Q = h^b.
        :param a, b: Secret values.
        :param p: Prime modulus (optional for large groups).
        """
        self._g = g
        self._h = h
        self._P = P
        self._Q = Q
        self._a = a
        self._b = b
        self._p = p
        self._random = random

    def commitment(self):
        """
        Generates commitments by the prover.
        :return: Tuple of commitments (g^r1, h^r2).
        """
        self._r1 = randint(self._p - 1)
        self._r2 = randint(self._p - 1)
        commitment1 = mod_exp(self._g, self._r1, self._p) 
        commitment2 = mod_exp(self._h, self._r2, self._p)
        return commitment1, commitment2

    def challenge(self):
        """
        Generates a challenge by the verifier.
        :return: Challenge (random integer).
        """
        self._challenge = randint(self._p - 1)
        return self._challenge

    def response(self):
        """
        Generates responses by the prover using the challenge.
        :param challenge: Challenge value from the verifier.
        :return: Tuple of responses (s1, s2).
        """
        s1 = (self._r1 + self._challenge *
              self._a) #% (self._p - 1)

        s2 = (self._r2 + self._challenge * self._b) #% (self._p - 1)
        return s1, s2

    def verify(self, commitment1, commitment2, response1, response2, challange):
        """
        Verifies the responses from the prover.
        """
        lhs1 = mod_exp(self._g, response1, self._p)
        lhs2 = mod_exp(self._h, response2, self._p) 
        rhs1 = commitment1 * (mod_exp(self._P, challange, self._p)) % self._p
        rhs2 = commitment2 * (mod_exp(self._Q, challange, self._p)) % self._p
        assert lhs1 == rhs1 and lhs2 == rhs2
        


if __name__ == "__main__":
    
    h = 3
    g = 5
    x = 762255500
    y = 215569921
    #p = 57896044618658097711785492504343953926634992332820282019728792003956564819968
    p = 170154366828665079503315635359566390626153860097410117673698414542663355444709893966571750073322692712277666971313348160841835991041384679700511912064982526249529596585220499141442747333138443745082395711957231040341599508490720584345044145678716964326909852653412051765274781142172235546768485104821112642811
    
    P = mod_exp(g, x, p)
    Q = mod_exp(h, y, p)
    
    client_a = DiscreteLogConjunctionInteractive(g, h, P, Q, p, x, y)
    client_b = DiscreteLogConjunctionInteractive(g, h, P, Q, p) 
    
    start_response = utime.ticks_us()
    
    t1, t2 = client_a.commitment()
    c = client_a.challenge()
    s1, s2 = client_a.response()
    
    end_response = utime.ticks_us()
    client_b.verify(t1, t2, s1, s2, c)
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )