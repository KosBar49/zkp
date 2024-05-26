import random 
import utime


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
        self._r1 = self._random.randint(
            0, self._p - 1)
        self._r2 = self._random.randint(
            0, self._p - 1)
        commitment1 = pow(self._g, self._r1, self._p) if self._p else pow(
            self._g, self._r1)
        commitment2 = pow(self._h, self._r2, self._p) if self._p else pow(
            self._h, self._r2)
        return commitment1, commitment2

    def challenge(self):
        """
        Generates a challenge by the verifier.
        :return: Challenge (random integer).
        """
        self._challenge = self._random.randint(
            1, self._p - 1)
        return self._challenge

    def response(self):
        """
        Generates responses by the prover using the challenge.
        :param challenge: Challenge value from the verifier.
        :return: Tuple of responses (s1, s2).
        """
        s1 = (self._r1 + self._challenge *
              self._a) % (self._p - 1)

        s2 = (self._r2 + self._challenge * self._b) % (self._p - 1)
        return s1, s2

    def verify(self, commitment1, commitment2, response1, response2, challange):
        """
        Verifies the responses from the prover.
        """
        lhs1 = pow(self._g, response1, self._p) if self._p else pow(
            self._g, response1)
        lhs2 = pow(self._h, response2, self._p) if self._p else pow(
            self._h, response2)
        rhs1 = (commitment1 * pow(self._P, challange, self._p)) % self._p
        rhs2 = (commitment2 * pow(self._Q, challange, self._p)) % self._p
        assert lhs1 == rhs1 and lhs2 == rhs2
        


if __name__ == "__main__":
 
    #generators 
    g = 2 
    h = 3
    # secrets
    x = 3
    y = 5 
    
    P = g ** x
    Q = h ** y 
    p = 5
    
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