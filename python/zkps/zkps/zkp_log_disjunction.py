import random
import hashlib
from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocol, ZeroKnowledgeProtocolNonInteractive
from .zkp_base import Base

class DiscreteLogDisjunctionInteractive(ZeroKnowledgeProtocol):
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
        self._random = random.SystemRandom()

    def challenge(self):
        """
        Generates a random challenge.

        :return: A random challenge c.
        """
        self._c = self._random.randint(1, self._p - 1)
        return self._c

    def commitment(self):
        """
        Generate commitment values for a cryptographic protocol.

        This function does not take any parameters and returns a tuple of two integers representing the commitment values.
        """
        self._r1 = self._random.randint(0, self._p - 1)
        self._s2 = self._random.randint(0, self._p - 1)
        self._c2 = self._random.randint(0, self._p - 1)
        t1 = pow(self._g, self._r1, self._p)

        t2 = (pow(self._h, self._s2, self._p) * pow(self._Q, - self._c2, self._p)) % self._p
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
        s1 = (self._r1 + c1 * self._x) % (self._p - 1)

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
        lhs1 = pow(g, s1, self._p)
        rhs1 = (t1 * pow(P, c1, self._p)) % self._p

        # Verify the second proof.
        lhs2 = pow(h, s2, self._p)
        rhs2 = (t2 * pow(Q, c2, self._p)) % self._p
        assert lhs2 == rhs2 and lhs1 == rhs1


class DiscreteLogDisjunction(ZeroKnowledgeProtocolNonInteractive, Base):

    def __init__(self, g, h, P, Q, p, x=None):
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
        self._random = random.SystemRandom()

    def response(self):
        r1 = self._random.randint(0, self._p - 1)
        c2 = self._random.randint(0, self._p - 1)
        s2 = self._random.randint(0, self._p - 1)

        t1 = pow(self._g, r1, self._p)
        t2 = (pow(self._h, s2, self._p) *
              pow(self._Q, (0 - c2), self._p)) % self._p
        
        c = self._hash([self._g, self._h, self._P, self._Q, t1, t2]) % self._p

        c1 = (c - c2) % self._p

        s1 = (r1 + c1 * self._x) % (self._p - 1)

        return (t1, c1, s1), (t2, c2, s2)

    def verify(self, g, h, P, Q, t1c1s1, t2c2s2):
        (t1, c1, s1) = t1c1s1
        (t2, c2, s2) = t2c2s2
        
        c = self._hash([g, h, P, Q, t1, t2]) % self._p

        assert (c == (c1 + c2) % self._p)

        lhs1 = pow(g, s1, self._p)
        rhs1 = (t1 * pow(P, c1, self._p)) % self._p

        lhs2 = pow(h, s2, self._p)
        rhs2 = (t2 * pow(Q, c2, self._p)) % self._p

        assert lhs1 == rhs1 and lhs2 == rhs2


class DiscreteLogDisjunctionEcc(ZeroKnowledgeProtocolNonInteractive):

    curve = get_curve('secp256r1')

    def __init__(self, x=None):
        if x:
            self._x = x

    def response(self, g, h, P, Q):

        r1 = DiscreteLogDisjunctionEcc.curve.get_random()
        c2 = DiscreteLogDisjunctionEcc.curve.get_random()
        s2 = DiscreteLogDisjunctionEcc.curve.get_random()

        t1 = DiscreteLogDisjunctionEcc.curve.scalar_mult(r1, g)
        t2 = DiscreteLogDisjunctionEcc.curve.point_add(DiscreteLogDisjunctionEcc.curve.scalar_mult(
            s2, h), DiscreteLogDisjunctionEcc.curve.scalar_mult((0-c2) % DiscreteLogDisjunctionEcc.curve.order, Q))
        c = DiscreteLogDisjunctionEcc.curve.hash_points([g, h, P, Q, t1, t2])
        c1 = (c - c2) % DiscreteLogDisjunctionEcc.curve.order
        s1 = ((r1 + c1 * self._x) %
              DiscreteLogDisjunctionEcc.curve.order) % DiscreteLogDisjunctionEcc.curve.order
        return (t1, c1, s1), (t2, c2, s2)

    def verify(self, g, h, P, Q, t1cs1, t2cs2):
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
        (t1, c1, s1) = t1cs1
        (t2, c2, s2) = t2cs2
        c = DiscreteLogDisjunctionEcc.curve.hash_points([g, h, P, Q, t1, t2])
        assert (c == (c1 + c2) % DiscreteLogDisjunctionEcc.curve.order)
        lhs1 = DiscreteLogDisjunctionEcc.curve.scalar_mult(s1, g)
        rhs1 = DiscreteLogDisjunctionEcc.curve.point_add(
            t1, DiscreteLogDisjunctionEcc.curve.scalar_mult(c1, P))
        lhs2 = DiscreteLogDisjunctionEcc.curve.scalar_mult(s2, h)
        rhs2 = DiscreteLogDisjunctionEcc.curve.point_add(
            t2, DiscreteLogDisjunctionEcc.curve.scalar_mult(c2, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
