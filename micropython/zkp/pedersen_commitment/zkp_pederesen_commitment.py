import random
import utime


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
        self.p = p
        self.x = x
        self.y = y
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

    def commit(self) -> int:
        """
        Generate a commitment.
        :return: The commitment value t.
        """
        self.r1 = self._random.randint(1, self.p - 1)
        self.r2 = self._random.randint(1, self.p - 1)
        self.t = (pow(self.g, self.r1, self.p) *
                  pow(self.h, self.r2, self.p)) % self.p
        return self.t

    def challenge(self) -> None:
        """
        Receives a challenge from the verifier.
        :param c: The challenge value.
        """
        self.c = self._random.randint(1, self.p - 1)
        return self.c

    def response(self, c) -> tuple:
        """
        Generate a response based on the challenge.
        :return: A tuple of the responses (s1, s2).
        """
        s1 = (self.r1 + c * self.x) % (self.p - 1)
        s2 = (self.r2 + c * self.y) % (self.p - 1)
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

        lhs = (pow(self.g, s1, self.p) * pow(self.h, s2, self.p)) % self.p
        # This is incorrect in the context of Pedersen commitments
        rhs = (t * pow(self.g, c, self.p)) % self.p
        # Correct rhs computation for Pedersen verification
        # rhs = t  # For Pedersen, the verification does not recompute t this way
        return lhs == rhs
    
if __name__ == "__main__":
    
    g = 2
    h = 3
    x = 5
    y = 7
    p = 1019
    
    client_a = PedersenCommitmentInteractive(g, h, p, x, y)
    client_b = PedersenCommitmentInteractive(g, h, p)

    start = utime.ticks_us()
    t = client_a.commit()
    c = client_b.challenge()
    s1, s2 = client_a.response(c)
    client_b.verify(t, c, s1, s2)
    
    end = utime.ticks_us()
    duration = (end - start) 
    
    print( f"time: {duration:.3f}" )