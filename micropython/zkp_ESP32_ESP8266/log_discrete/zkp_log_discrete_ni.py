import random
import hashlib
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

class DiscreteLog():
    """
    Implementation based on https://asecuritysite.com/zero/nizkp2
    """

    def __init__(self, g, y, p, x=None):
        """
        :param g: generator
        :param y: public key
        :param p: modulo
        :param x: secret
        """
        self._g = g
        self._p = p
        self._y = y
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
        Calculate the response value based on the current state of the object.
        Returns:
            int: The calculated response value.
        """
        self._v = randint(self._p)
        t = mod_exp(self._g, self._v, self._p)
        self._c = self._hash([self._g, self._y, t])
        return t, (self._v - self._c * self._x) #% (self._p - 1)

    def verify(self, s, t):
        """
        Verify the validity of a given signature.
        Parameters:
            r (int): The r value of the signature.
            c (int): The c value of the signature.
            V (int): The V value of the signature.
        Returns:
            None
        Raises:
            AssertionError: If the signature is invalid.
        """        
        c = self._hash([self._g, self._y, t])
        check = ( mod_exp(self._g, s, self._p) * mod_exp(self._y, c, self._p)) % self._p
        assert t == check

if __name__ == "__main__":

    g = 5
    x = 762255500
    p = 170154366828665079503315635359566390626153860097410117673698414542663355444709893966571750073322692712277666971313348160841835991041384679700511912064982526249529596585220499141442747333138443745082395711957231040341599508490720584345044145678716964326909852653412051765274781142172235546768485104821112642811
    #p = 57896044618658097711785492504343953926634992332820282019728792003956564819968
    P = mod_exp(g, x, p)

    client_a = DiscreteLog(g, P, p, x)
    client_b = DiscreteLog(g, P, p)
    
    start_response = utime.ticks_us()

    t, s = client_a.response()
    end_response = utime.ticks_us()

    client_b.verify(s, t)
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )