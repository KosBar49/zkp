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

    def challenge(self):
        """
        Generates a random challenge.

        :return: A random challenge c.
        """
        self._c = randint(self._p - 1)
        return self._c

    def commitment(self):
        """
        Generate commitment values for a cryptographic protocol.

        This function does not take any parameters and returns a tuple of two integers representing the commitment values.
        """
        self._r1 = randint(self._p - 1)
        self._s2 = randint(self._p - 1)
        self._c2 = randint(self._p - 1)
        t1 = mod_exp(self._g, self._r1, self._p)

        
        p1 = mod_exp(self._h, self._s2, self._p)
        p2 = mod_exp(self._Q, -self._c2, self._p)
        
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
        s1 = (self._r1 + c1 * self._x) #% (self._p - 1)

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
        lhs1 = mod_exp(g, s1, self._p)
        rhs1 = (t1 * mod_exp(P, c1, self._p)) % self._p

        # Verify the second proof.
        lhs2 = mod_exp(h, s2, self._p)
        rhs2 = (t2 * mod_exp(Q, c2, self._p)) % self._p
        #print(f"lhs1: {lhs1}, lhs2: {lhs2}, rhs1: {rhs1}, rhs2: {rhs2}")
        assert lhs2 == rhs2 and lhs1 == rhs1
        
    
if __name__ == "__main__":
    
    h = 3
    g = 5
    x = 762255500
    y = 215569921
    #p = 57896044618658097711785492504343953926634992332820282019728792003956564819968
    p = 170154366828665079503315635359566390626153860097410117673698414542663355444709893966571750073322692712277666971313348160841835991041384679700511912064982526249529596585220499141442747333138443745082395711957231040341599508490720584345044145678716964326909852653412051765274781142172235546768485104821112642811
    P = mod_exp(g, x, p)
    Q = mod_exp(h, y, p)
    
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