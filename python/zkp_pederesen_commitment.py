from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocolNonInteractive


class PedersenCommitment(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None, y = None) -> None:
        if x and y:
            self._x = x
            self._y = y
            
    def response(self, g, h, P):
        r1 = PedersenCommitment.curve.get_random()
        r2 = PedersenCommitment.curve.get_random()
        
        t = PedersenCommitment.curve.point_add(PedersenCommitment.curve.scalar_mult(r1, g), PedersenCommitment.curve.scalar_mult(r2, h))
        c = PedersenCommitment.curve.hash_points( [ g, h, P, t ] )
        s1 = ((r1 + c * self._x) % PedersenCommitment.curve.order )
        s2 = ((r2 + c * self._y) % PedersenCommitment.curve.order )
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
        lhs = PedersenCommitment.curve.point_add(PedersenCommitment.curve.scalar_mult(s1, g), PedersenCommitment.curve.scalar_mult(s2, h))
        c = PedersenCommitment.curve.hash_points([g, h, P, t])
        rhs = PedersenCommitment.curve.point_add(t , PedersenCommitment.curve.scalar_mult(c, P))
        assert (lhs == rhs)