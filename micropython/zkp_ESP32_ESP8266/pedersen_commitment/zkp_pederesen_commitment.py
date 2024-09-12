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

class PedersenCommitmentInteractive():
    """
    Interactive Pedersen Commitment in a cyclic group of prime order.
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
        self._p = p
        self.x = x
        self.y = y

    def commit(self) -> int:
        """
        Generate a commitment.
        :return: The commitment value t.
        """
        self.r1 = randint(self._p - 1)
        self.r2 = randint(self._p - 1)
        self.t = (mod_exp(self.g, self.r1, self._p) *
                  mod_exp(self.h, self.r2, self._p)) % self._p
        return self.t

    def challenge(self) -> None:
        """
        Receives a challenge from the verifier.
        :param c: The challenge value.
        """
        self.c = randint(self._p - 1)
        return self.c

    def response(self, c) -> tuple:
        """
        Generate a response based on the challenge.
        :return: A tuple of the responses (s1, s2).
        """
        s1 = (self.r1 + c * self.x) #% (self._p - 1)
        s2 = (self.r2 + c * self.y) #% (self._p - 1)
        return s1, s2

    def verify(self, t: int, c: int, s1: int, s2: int) -> bool:
        """
        Verify the validity of a given commitment and responses.
        :param t: The commitment value.
        :param c: The challenge value.
        :param s1: The first response value.
        :param s2: The second response value.
        :return: True if the verification is successful, False otherwise.
        """
        # Recompute the commitment using s1, s2, and challenge c

        lhs = (mod_exp(self.g, s1, self._p) * mod_exp(self.h, s2, self._p)) % self._p
        # This is incorrect in the context of Pedersen commitments
        rhs = (t * mod_exp(self.g, c, self._p)) % self._p
        # Correct rhs computation for Pedersen verification
        # rhs = t  # For Pedersen, the verification does not recompute t this way
        return lhs == rhs
    
if __name__ == "__main__":
    
    g = 5
    h = 3
    x = 762255500
    y = 215569921

    #p = 57896044618658097711785492504343953926634992332820282019728792003956564819968
    p = 170154366828665079503315635359566390626153860097410117673698414542663355444709893966571750073322692712277666971313348160841835991041384679700511912064982526249529596585220499141442747333138443745082395711957231040341599508490720584345044145678716964326909852653412051765274781142172235546768485104821112642811
    client_a = PedersenCommitmentInteractive(g, h, p, x, y)
    client_b = PedersenCommitmentInteractive(g, h, p)

    start_response = utime.ticks_us()
    t = client_a.commit()
    c = client_b.challenge()
    s1, s2 = client_a.response(c)
    end_response = utime.ticks_us()
    client_b.verify(t, c, s1, s2)
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )