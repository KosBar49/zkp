import random
from typing import Tuple
from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocol, ZeroKnowledgeProtocolNonInteractive
from .zkp_base import Base

class DiscreteLogEqualityInteractive(ZeroKnowledgeProtocol):
    """
    Implementation of a Zero-Knowledge Proof protocol for discrete logarithm equality.
    """

    def __init__(self, g: int, h: int,xG: int, xH: int, p: int, x: int = None):
        self._p = p
        self._g = g
        self._xG = xG
        self._h = h
        self._xH = xH
        self._x = x
        # Use cryptographically secure random generator
        self._random = random.SystemRandom()

    def commitments(self) -> Tuple[int, int]:
        """
        Generates commitments for the protocol.
        """
        self._v = self._random.randint(0, self._p - 1)
        self._vG = pow(self._g, self._v, self._p)
        self._vH = pow(self._h, self._v, self._p)
        return self._vG, self._vH

    def challenge(self) -> int:
        """
        Generates a random challenge value.
        """
        self._c = self._random.randint(1, self._p - 1)
        return self._c

    def response(self, c: int) -> int:
        """
        Calculates the response based on the challenge.
        """
        self._r = (self._v - self._x * c) % (self._p - 1)
        return self._r

    def verify(self, c: int, r: int, vG: int, vH: int) -> bool:
        """
        Verifies the ZKP given the challenge, response, and commitments.
        """
        # Calculate the verification values using the prover's response
        v1 = pow(self._g, r, self._p) * pow(self._xG, c, self._p) % self._p
        v2 = pow(self._h, r, self._p) * pow(self._xH, c, self._p) % self._p

        # Check if the recalculated commitments match the original commitments
        assert v1 == vG
        assert v2 == vH


class DiscreteLogEquality(ZeroKnowledgeProtocolNonInteractive, Base):
    """
    Implementation based on https://asecuritysite.com/zero/dleq3
    """

    def __init__(self, g, h, P, Q, p, x=None):
        """
        :param g: generator 1
        :param xG: public key 1
        :param h: generator 2
        :param xH: public key 2
        :param p: modulo
        :param x: secret
        """
        self._g = g
        self._P = P
        self._h = h
        self._Q = Q
        self._p = p
        self._x = x
        self._random = random.SystemRandom()

    def response(self):
        """
        Calculates the response value based on the current object state.
        :return: The calculated response value.
        """
        self._v = self._random.randint(0, self._p - 1)
        self._vG = pow(self._g, self._v, self._p)
        self._vH = pow(self._h, self._v, self._p)
        
        self._c = self._hash([self._vG, self._vH, self._g, self._h])

        self._r = (self._v - self._x * self._c) % (self._p - 1)
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
        v1 = (pow(self._g, r, self._p) * pow(self._P, c, self._p)) % self._p
        v2 = (pow(self._h, r, self._p) * pow(self._Q, c, self._p)) % self._p
        
        c1 = self._hash([v1, v2, self._g, self._h])
        assert c == c1


class DiscreteLogEqualityEcc(ZeroKnowledgeProtocolNonInteractive):

    curve = get_curve('secp256r1')

    def __init__(self, x=None):
        """
        Initializes an instance of the class.

        Parameters:
            x (optional): The value to assign to the private attribute _x.

        Returns:
            None
        """
        if x:
            self._x = x

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
        r = DiscreteLogEqualityEcc.curve.get_random()
        t1 = DiscreteLogEqualityEcc.curve.mult_point(r, g)
        t2 = DiscreteLogEqualityEcc.curve.mult_point(r, h)
        c = DiscreteLogEqualityEcc.curve.hash_points([g, h, P, Q, t1, t2])
        s = ((r + c * self._x) % DiscreteLogEqualityEcc.curve.order)
        return t1, t2, s

    def verify(self, g, h, P, Q, t1, t2, s):
        """
        Verify the equality of two discrete logarithms.
        Args:
            g (Point): The base point of the first logarithm.
            h (Point): The base point of the second logarithm.
            P (Point): The first point on the elliptic curve.
            Q (Point): The second point on the elliptic curve.
            t1 (Point): The first temporary point.
            t2 (Point): The second temporary point.
            s (Scalar): The scalar value.
        Returns:
            None
        Raises:
            AssertionError: If the equality of the discrete logarithms is not verified.
        """
        c = DiscreteLogEqualityEcc.curve.hash_points([g, h, P, Q, t1, t2])
        lhs1 = DiscreteLogEqualityEcc.curve.mult_point(s, g)
        rhs1 = DiscreteLogEqualityEcc.curve.point_add(
            t1, DiscreteLogEqualityEcc.curve.mult_point(c, P))
        lhs2 = DiscreteLogEqualityEcc.curve.mult_point(s, h)
        rhs2 = DiscreteLogEqualityEcc.curve.point_add(
            t2, DiscreteLogEqualityEcc.curve.mult_point(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
