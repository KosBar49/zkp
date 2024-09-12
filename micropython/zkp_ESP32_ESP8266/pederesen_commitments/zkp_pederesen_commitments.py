import random
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

class PedersenCommitmentsEqualInteractive():
    def __init__(self, p, x=None, y=None):
        self._x = x
        self._y = y
        self._p = p  # Large prime number for p operations

    def challenge(self):
        """Verifier generates and sends a random challenge to the prover."""
        self._c = randint(self._p - 1)
        return self._c

    def response(self, g1, h1, g2, h2, c):
        """Prover computes the response to the challenge."""
        r1 = randint(self._p - 1)
        r2 = randint(self._p - 1)
        
        t1 = (mod_exp(g1, r1, self._p ) * mod_exp(h1, r2, self._p)) % self._p
        t2 = (mod_exp(g2, r1, self._p ) * mod_exp(h2, r2, self._p)) % self._p
        
        s1 = (r1 + c * self._x) #% (self.p - 1)
        s2 = (r2 + c * self._y) #% (self.p - 1)
        
        return (t1, s1), (t2, s2)

    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        """Verifier checks the prover's response against the given challenge."""
        lhs1 = (mod_exp(g1, s1, self._p) * mod_exp(h1, s2, self._p)) % self._p
        lhs2 = (mod_exp(g2, s1, self._p) * mod_exp(h2, s2, self._p)) % self._p
        
        rhs1 = (t1 * mod_exp(P, self._c, self._p)) % self._p
        rhs2 = (t2 * mod_exp(Q, self._c, self._p)) % self._p
        
        assert lhs1 == rhs1 
        assert lhs2 == rhs2
        
if __name__ == "__main__":
    
    g = 5
    h = 3
    h2 = 7
    g2 = 9
    x = 762255500
    y = 215569921
    z = 315511233
    #p = 57896044618658097711785492504343953926634992332820282019728792003956564819968
    p = 170154366828665079503315635359566390626153860097410117673698414542663355444709893966571750073322692712277666971313348160841835991041384679700511912064982526249529596585220499141442747333138443745082395711957231040341599508490720584345044145678716964326909852653412051765274781142172235546768485104821112642811
    P = (mod_exp(g, x, p) * mod_exp(h, y, p) ) % p
    Q = (mod_exp(g2, x, p) * mod_exp(h2, y, p) ) % p    

    client_a = PedersenCommitmentsEqualInteractive(p, x, y)
    client_b = PedersenCommitmentsEqualInteractive(p)
    
    c = client_b.challenge()
    
    start_response= utime.ticks_us()

    t1s1, t2s2 = client_a.response(g, h, g2, h2, c)
    
    end_response = utime.ticks_us()

    client_b.verify(g, h, g2, h2, P, Q, t1s1, t2s2)
    
    end_verify = utime.ticks_us()

    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )