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


class DiscreteLogConjunction():

    def __init__(self, g, h, P, Q, p, x=None, y=None):
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
        self._y = y
        self._random = random
        
    def _hash(self, itmes):
        s_ = ''
        h = hashlib.sha256()
        for item in itmes:      
            s_ += str(item)
        h.update(s_.encode())
        return int(h.digest().hex(), 16)

    def response(self):
        r1 = randint(self._p - 1)
        r2 = randint(self._p - 1)

        t1 = mod_exp(self._g, r1, self._p)
        t2 = mod_exp(self._h, r2, self._p)

        c = self._hash([self._g, self._h, self._P, self._Q, t1, t2]) % self._p
        
        s1 = (r1 + c * self._x) #% (self._p - 1)
        s2 = (r2 + c * self._y) #% (self._p - 1)

        return (t1, s1), (t2, s2)

    def verify(self, t1cs1, t2cs2):

        (t1, s1) = t1cs1
        (t2, s2) = t2cs2

        c = self._hash([self._g, self._h, self._P, self._Q, t1, t2]) % self._p
        
        lhs1 = mod_exp(self._g, s1, self._p)
        rhs1 = (t1 * mod_exp(self._P, c, self._p)) % self._p

        lhs2 = mod_exp(self._h, s2, self._p)
        rhs2 = (t2 * mod_exp(self._Q, c, self._p)) % self._p

        assert lhs1 == rhs1
        assert lhs2 == rhs2

if __name__ == "__main__":

    h = 3
    g = 5
    x = 762255500
    y = 215569921
    #p = 57896044618658097711785492504343953926634992332820282019728792003956564819968
    p = 170154366828665079503315635359566390626153860097410117673698414542663355444709893966571750073322692712277666971313348160841835991041384679700511912064982526249529596585220499141442747333138443745082395711957231040341599508490720584345044145678716964326909852653412051765274781142172235546768485104821112642811
    
    P = mod_exp(g, x, p)
    Q = mod_exp(h, y, p)
    
    client_a = DiscreteLogConjunction(g, h, P, Q, p, x, y)
    client_b = DiscreteLogConjunction(g, h, P, Q, p) 
    
    start_response = utime.ticks_us()
    
    (t1, s1), (t2, s2) = client_a.response()
    
    end_response = utime.ticks_us()

    client_b.verify((t1, s1), (t2, s2))
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )