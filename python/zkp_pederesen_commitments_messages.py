from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocolNonInteractive


class PederesenCommitmentsEqualMessages(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    def __init__(self, x = None, y = None, z = None) -> None:
        if x and y and z:
            self._x = x
            self._y = y
            self._z = z
    
    def response(self, g1, h1, g2, h2, P, Q):
        r1 = PederesenCommitmentsEqualMessages.curve.get_random()
        r2 = PederesenCommitmentsEqualMessages.curve.get_random()
        r3 = PederesenCommitmentsEqualMessages.curve.get_random()
        
        t1 = PederesenCommitmentsEqualMessages.curve.point_add(PederesenCommitmentsEqualMessages.curve.scalar_mult(r1, g1), PederesenCommitmentsEqualMessages.curve.scalar_mult(r2, h1))
        t2 = PederesenCommitmentsEqualMessages.curve.point_add(PederesenCommitmentsEqualMessages.curve.scalar_mult(r1, g2), PederesenCommitmentsEqualMessages.curve.scalar_mult(r3, h2))
        
        c = PederesenCommitmentsEqualMessages.curve.hash_points( [ g1, h1, g2, h2, P, Q, t1, t2 ] )
        
        s1 = ((r1 + c * self._x) % PederesenCommitmentsEqualMessages.curve.order )
        s2 = ((r2 + c * self._y) % PederesenCommitmentsEqualMessages.curve.order )
        s3 = ((r3 + c * self._z) % PederesenCommitmentsEqualMessages.curve.order )
        return (t1, s1), (t2, s2), s3
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2, s3):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        lhs1 = PederesenCommitmentsEqualMessages.curve.point_add(PederesenCommitmentsEqualMessages.curve.scalar_mult(s1, g1), PederesenCommitmentsEqualMessages.curve.scalar_mult(s2, h1))
        lhs2 = PederesenCommitmentsEqualMessages.curve.point_add(PederesenCommitmentsEqualMessages.curve.scalar_mult(s1, g2), PederesenCommitmentsEqualMessages.curve.scalar_mult(s3, h2))
        c = PederesenCommitmentsEqualMessages.curve.hash_points([g1, h1, g2, h2, P, Q, t1, t2])
        rhs1 = PederesenCommitmentsEqualMessages.curve.point_add(t1 , PederesenCommitmentsEqualMessages.curve.scalar_mult(c, P))
        rhs2 = PederesenCommitmentsEqualMessages.curve.point_add(t2 , PederesenCommitmentsEqualMessages.curve.scalar_mult(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)