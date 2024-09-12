import random
# import utime
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

    def commitments(self):
        """
        Generates commitments for the protocol.
        """
        self._v = 26211229949366594240734546754800349145751146553389310720601189706030232364193 #randint(self._p - 1)
        print(self._v)
        self._vG = mod_exp(self._g, self._v, self._p)
        print(f"vG: {self._vG}")
        self._vH = mod_exp(self._h, self._v, self._p)
        print(f"vH: {self._vH}")
        return self._vG, self._vH

    def challenge(self) -> int:
        """
        Generates a random challenge value.
        """
        self._c = 36012301591122411747432064042255888726810852711039282800059221339516455273659 #randint(self._p - 1)
        return self._c

    def response(self, c: int) -> int:
        """
        Calculates the response based on the challenge.
        """
        self._r = (self._v - self._x * c) #% (self._p - 1)
        return self._r

    def verify(self, c: int, r: int, vG: int, vH: int) -> bool:
        """
        Verifies the ZKP given the challenge, response, and commitments.
        """
        # Calculate the verification values using the prover's response
        print(f"g: {self._g}")
        print(f"r {r}")
        print(f"first: {mod_exp(self._g, r, self._p)}")
        v1 = (mod_exp(self._g, r, self._p) * mod_exp(self._xG, c, self._p )) % self._p
        v2 = (mod_exp(self._h, r, self._p) * mod_exp(self._xH, c, self._p )) % self._p

        # Check if the recalculated commitments match the original commitments
        print(f"v1: {v1}")
        print(f"vG: {vG}")
        print(f"v2: {v2}")
        print(f"vH: {vH}")
        assert v1 == vG
        assert v2 == vH

if __name__ == "__main__":
    
    g = 5
    h = 3
    x = 762255500
    p = 57896044618658097711785492504343953926634992332820282019728792003956564819968
        
    P = mod_exp(g, x, p)
    Q = mod_exp(h, x, p)

    client_a = DiscreteLogDisjunctionInteractive(g, h, P, Q, p, x)
    client_b = DiscreteLogDisjunctionInteractive(g, h, P, Q, p)
    
    #start_response = utime.ticks_us()

    t1, t2 = client_a.commitments()
    
    c = client_b.challenge()
    
    s = client_a.response(c)
    
    #end_response = utime.ticks_us()
    
    client_b.verify(c, s, t1, t2)
    
    #end_verify = utime.ticks_us()

    #print( f"time of verify: {end_verify - end_response:.3f}" )
    #print( f"time of response: {end_response - start_response:.3f}" )