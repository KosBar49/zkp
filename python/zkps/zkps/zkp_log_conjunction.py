import random
from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocol, ZeroKnowledgeProtocolNonInteractive
from .zkp_base import Base

    
class DiscreteLogConjunctionInteractive(ZeroKnowledgeProtocol):

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
        self._random = random.SystemRandom()

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


class DiscreteLogConjunction(ZeroKnowledgeProtocolNonInteractive, Base):

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
        self._random = random.SystemRandom()

    def response(self):
        r1 = self._random.randint(0, self._p - 1)
        r2 = self._random.randint(0, self._p - 1)

        t1 = pow(self._g, r1, self._p)
        t2 = pow(self._h, r2, self._p)

        c = self._hash([self._g, self._h, self._P, self._Q, t1, t2]) % self._p
        
        s1 = (r1 + c * self._x) % (self._p - 1)
        s2 = (r2 + c * self._y) % (self._p - 1)

        return (t1, s1), (t2, s2)

    def verify(self, t1cs1, t2cs2):

        (t1, s1) = t1cs1
        (t2, s2) = t2cs2

        c = self._hash([self._g, self._h, self._P, self._Q, t1, t2]) % self._p
        
        lhs1 = pow(self._g, s1, self._p)
        rhs1 = (t1 * pow(self._P, c, self._p)) % self._p

        lhs2 = pow(self._h, s2, self._p)
        rhs2 = (t2 * pow(self._Q, c, self._p)) % self._p

        assert lhs1 == rhs1
        assert lhs2 == rhs2


class DiscreteLogConjunctionEcc(ZeroKnowledgeProtocolNonInteractive):

    curve = get_curve('secp256r1')

    def __init__(self, x=None, y=None):

        if x and y:
            self._x = x
            self._y = y

    def response(self, g, h, P, Q):
        """
        Calculates the response for the given parameters.
        Args:
            g (Point): The base point of the curve.
            h (Point): Another point on the curve.
            P (Point): A point on the curve.
            Q (Point): Another point on the curve.
        Returns:
            Tuple[Point, Point, int]: A tuple containing the calculated points t1 and t2, and the calculated integer s.
        """
        r1 = DiscreteLogConjunctionEcc.curve.get_random()
        r2 = DiscreteLogConjunctionEcc.curve.get_random()
        t1 = DiscreteLogConjunctionEcc.curve.mult_point(r1, g)
        t2 = DiscreteLogConjunctionEcc.curve.mult_point(r2, h)
        c = DiscreteLogConjunctionEcc.curve.hash_points([g, h, P, Q, t1, t2])
        s1 = ((r1 + c * self._x) % DiscreteLogConjunctionEcc.curve.order)
        s2 = ((r2 + c * self._y) % DiscreteLogConjunctionEcc.curve.order)
        return (t1, s1), (t2, s2)

    def verify(self, g, h, P, Q, t1s1, t2s2):
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
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        c = DiscreteLogConjunctionEcc.curve.hash_points([g, h, P, Q, t1, t2])
        lhs1 = DiscreteLogConjunctionEcc.curve.mult_point(s1, g)
        rhs1 = DiscreteLogConjunctionEcc.curve.point_add(
            t1, DiscreteLogConjunctionEcc.curve.mult_point(c, P))
        lhs2 = DiscreteLogConjunctionEcc.curve.mult_point(s2, h)
        rhs2 = DiscreteLogConjunctionEcc.curve.point_add(
            t2, DiscreteLogConjunctionEcc.curve.mult_point(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
