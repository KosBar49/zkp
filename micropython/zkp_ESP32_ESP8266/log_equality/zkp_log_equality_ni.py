import hashlib
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
        self._v = randint(self._p - 1)
        self._vG = mod_exp(self._g, self._v, self._p)
        self._vH = mod_exp(self._h, self._v, self._p)
        
        self._c = self._hash([self._vG, self._vH, self._g, self._h])

        self._r = (self._v - self._x * self._c) #% (self._p - 1)
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
        v1 = ( ( mod_exp(self._g, r, self._p) ) * (mod_exp(self._P, c, self._p))) % self._p
        v2 = ( ( mod_exp(self._h, r, self._p )) * (mod_exp(self._Q, c, self._p))) % self._p
        
        c1 = self._hash([v1, v2, self._g, self._h])
        assert c == c1

if __name__ == "__main__":
    
    g = 5
    h = 3
    x = 762255500
    #p = 57896044618658097711785492504343953926634992332820282019728792003956564819968
    p = 170154366828665079503315635359566390626153860097410117673698414542663355444709893966571750073322692712277666971313348160841835991041384679700511912064982526249529596585220499141442747333138443745082395711957231040341599508490720584345044145678716964326909852653412051765274781142172235546768485104821112642811
    P = mod_exp(g, x, p)
    Q = mod_exp(h, x ,p)
    
    client_a = DiscreteLogEquality(g, h, P, Q, p, x)
    client_b = DiscreteLogEquality(g, h, P, Q, p)
    
    start_response = utime.ticks_us()
    c, s = client_a.response()
    end_response = utime.ticks_us()
    client_b.verify(c, s)
    
    end_verify = utime.ticks_us()

    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )