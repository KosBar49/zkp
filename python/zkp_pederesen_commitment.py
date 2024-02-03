from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocolNonInteractive


class PedersenCommitmentEcc(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None, y = None) -> None:
        if x and y:
            self._x = x
            self._y = y
            
    def response(self, g, h, P):
        r1 = PedersenCommitmentEcc.curve.get_random()
        r2 = PedersenCommitmentEcc.curve.get_random()
        
        t = PedersenCommitmentEcc.curve.point_add(PedersenCommitmentEcc.curve.scalar_mult(r1, g), PedersenCommitmentEcc.curve.scalar_mult(r2, h))
        c = PedersenCommitmentEcc.curve.hash_points( [ g, h, P, t ] )
        s1 = ((r1 + c * self._x) % PedersenCommitmentEcc.curve.order )
        s2 = ((r2 + c * self._y) % PedersenCommitmentEcc.curve.order )
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
        lhs = PedersenCommitmentEcc.curve.point_add(PedersenCommitmentEcc.curve.scalar_mult(s1, g), PedersenCommitmentEcc.curve.scalar_mult(s2, h))
        c = PedersenCommitmentEcc.curve.hash_points([g, h, P, t])
        rhs = PedersenCommitmentEcc.curve.point_add(t , PedersenCommitmentEcc.curve.scalar_mult(c, P))
        assert (lhs == rhs)