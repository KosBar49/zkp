from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocol, ZeroKnowledgeProtocolNonInteractive

import random
import hashlib


class PedersenCommitmentInteractive(ZeroKnowledgeProtocol):
    """
    Interactive Pedersen Commitment in a cyclic group of prime order.
    """

    def __init__(self, p: int, g: int, h: int, x: int = None, y: int = None) -> None:
        """
        Initialize the commitment scheme with public parameters and optionally secret values.
        :param p: The prime order of the cyclic group.
        :param g: The generator of the group.
        :param h: Another generator of the group, where no one knows the discrete log of h with respect to g.
        :param x: The secret value associated with g.
        :param y: The secret value associated with h.
        """
        self.p = p
        self.g = g
        self.h = h
        self.x = x
        self.y = y
        self._random = random.SystemRandom()

    def commit(self) -> int:
        """
        Generate a commitment.
        :return: The commitment value t.
        """
        self.r1 = random.randint(1, self.p - 1)
        self.r2 = random.randint(1, self.p - 1)
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


class PedersenCommitment(ZeroKnowledgeProtocolNonInteractive):
    """
    Non-interactive Pedersen Commitment in a cyclic group of prime order.
    """

    def __init__(self, p: int, g: int, h: int, x: int = None, y: int = None) -> None:
        """
        Initialize the commitment scheme with public parameters and optionally secret values.
        :param p: The prime order of the cyclic group.
        :param g: The generator of the group.
        :param h: Another generator of the group, where no one knows the discrete log of h with respect to g.
        :param x: The secret value associated with g.
        :param y: The secret value associated with h.
        """
        self.p = p
        self.g = g
        self.h = h
        self.x = x
        self.y = y

    def response(self, P: int) -> tuple:
        """
        Generate a commitment and response for the given value P.
        :param P: The public point (or value) associated with the secrets x and y.
        :return: A tuple of the commitment (t), and responses (s1, s2).
        """
        r1 = random.randint(1, self.p - 1)
        r2 = random.randint(1, self.p - 1)

        # Commitment
        t = (pow(self.g, r1, self.p) * pow(self.h, r2, self.p)) % self.p
        cha1 = str(self.g) + str(self.h) + str(P) + str(t)
        hash_ = hashlib.md5()
        hash_.update(cha1.encode())
        c = int(hash_.hexdigest(), 16) % self.p

        # Responses
        s1 = (r1 + c * self.x) % (self.p - 1)
        s2 = (r2 + c * self.y) % (self.p - 1)

        return t, s1, s2

    def verify(self, g: int, h: int, P: int, t: int, s1: int, s2: int) -> bool:
        """
        Verify the validity of a given commitment and responses.
        :param g, h: The generators.
        :param P: The public point/value.
        :param t: The commitment.
        :param s1, s2: The responses.
        :return: True if the commitment and responses are valid, False otherwise.
        """
        # Calculate left hand side (LHS) of the verification equation
        lhs = (pow(g, s1, self.p) * pow(h, s2, self.p)) % self.p
        cha1 = str(g) + str(h) + str(P) + str(t)
        hash_ = hashlib.md5()
        hash_.update(cha1.encode())
        c = int(hash_.hexdigest(), 16) % self.p

        # Calculate right hand side (RHS) of the verification equation
        rhs = (t * pow(P, c, self.p)) % self.p

        assert lhs == rhs


class PedersenCommitmentEcc(ZeroKnowledgeProtocolNonInteractive):

    curve = get_curve('secp256r1')

    def __init__(self, x=None, y=None) -> None:
        if x and y:
            self._x = x
            self._y = y

    def response(self, g, h, P):
        r1 = PedersenCommitmentEcc.curve.get_random()
        r2 = PedersenCommitmentEcc.curve.get_random()

        t = PedersenCommitmentEcc.curve.point_add(PedersenCommitmentEcc.curve.scalar_mult(
            r1, g), PedersenCommitmentEcc.curve.scalar_mult(r2, h))
        c = PedersenCommitmentEcc.curve.hash_points([g, h, P, t])
        s1 = ((r1 + c * self._x) % PedersenCommitmentEcc.curve.order)
        s2 = ((r2 + c * self._y) % PedersenCommitmentEcc.curve.order)
        return t, s1, s2

    def verify(self, g, h, P, t, s1, s2):
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
        lhs = PedersenCommitmentEcc.curve.point_add(PedersenCommitmentEcc.curve.scalar_mult(
            s1, g), PedersenCommitmentEcc.curve.scalar_mult(s2, h))
        c = PedersenCommitmentEcc.curve.hash_points([g, h, P, t])
        rhs = PedersenCommitmentEcc.curve.point_add(
            t, PedersenCommitmentEcc.curve.scalar_mult(c, P))
        assert (lhs == rhs)
