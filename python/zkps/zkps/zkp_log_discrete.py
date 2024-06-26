import random
from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocol, ZeroKnowledgeProtocolNonInteractive
from .zkp_base import Base

class DiscreteLogInteractive(ZeroKnowledgeProtocol):

    def __init__(self, g, y, p, x=None):
        """
        :param g: generator
        :param y: public key
        :param p: modulo
        :param x: secret
        """
        self._g = g
        self._y = y
        self._p = p
        self._x = x
        self._random = random.SystemRandom()

    def commitment(self):
        """
        :return: commitment (g^r mod p)
        """
        self._r = self._random.randint(0, self._p - 1)
        commitment = pow(self._g, self._r, self._p)
        return commitment

    def challenge(self):
        """        
        :return: challenge (x * c + r mod p - 1)
        """
        self._challenge = self._random.randint(1, self._p - 1)
        return self._challenge

    def response(self, challenge):
        """
        :param challenge: The challenge generated by the verifier

        :return: response (x * c + r mod p - 1)
        """
        return (self._x * challenge + self._r) % (self._p - 1)

    def verify(self, response, commitment):
        """
        :param response: The response generated by the prover
        :param commitment: The commitment generated by the prover
        """
        assert pow(self._g, response, self._p) == (
            pow(self._y, self._challenge) * commitment) % self._p


class DiscreteLog(ZeroKnowledgeProtocolNonInteractive, Base):
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
        self._random = random.SystemRandom()

    def response(self):
        """
        Calculate the response value based on the current state of the object.
        Returns:
            int: The calculated response value.
        """
        self._v = self._random.randint(0, self._p - 1)
        t = pow(self._g, self._v, self._p)
        self._c = self._hash([self._g, self._y, t])
        print(f"c: {self._c}")
        return t, (self._v - self._c * self._x) % (self._p - 1)

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
        check = (pow(self._g, s, self._p) * pow(self._y, c, self._p)) % self._p
        assert t == check


class DiscreteLogEcc(ZeroKnowledgeProtocolNonInteractive):

    curve = get_curve('secp256r1')

    def __init__(self, x=None):
        """
        Initializes the object with an optional value for x.
        Parameters:
            x (optional): An optional value for x.
        Returns:
            None
        """
        if x:
            self._x = x
            DiscreteLogEcc.y = DiscreteLogEcc.curve.mult_point(
                x, DiscreteLogEcc.curve.g)

    def response(self):
        """
        Generate a response using the DiscreteLogNonInteractiveEcc algorithm.

        Returns:
            tuple: A tuple containing the calculated values t and s.
                - t (Point): The calculated point t.
                - s (int): The calculated value s.
        """
        r = DiscreteLogEcc.curve.get_random()
        t = DiscreteLogEcc.curve.mult_point(r, DiscreteLogEcc.curve.g)
        c = DiscreteLogEcc.curve.hash_points(
            [DiscreteLogEcc.curve.g, DiscreteLogEcc.y, t])
        s = ((r + c * self._x) % DiscreteLogEcc.curve.order)
        return t, s

    def verify(self, s, t):
        """
        Verify the equality of two values by performing a discrete logarithm non-interactive elliptic curve cryptography (ECC) verification.

        Args:
            t: The first value to be verified.
            s: The second value to be verified.

        Returns:
            None

        Raises:
            AssertionError: If the verification fails (i.e., the values are not equal).
        """
        c = DiscreteLogEcc.curve.hash_points(
            [DiscreteLogEcc.curve.g, DiscreteLogEcc.y, t])
        lhs = DiscreteLogEcc.curve.mult_point(s, DiscreteLogEcc.curve.g)
        yc = DiscreteLogEcc.curve.mult_point(c, DiscreteLogEcc.y)
        rhs = DiscreteLogEcc.curve.point_add(t, yc)
        assert lhs == rhs
