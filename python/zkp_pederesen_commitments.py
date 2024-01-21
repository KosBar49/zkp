from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocolNonInteractive

class PederesenCommitmentsEqual(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None, y = None) -> None:
        if x and y:
            self._x = x
            self._y = y
            
    def response(self, g1, h1, g2, h2, P, Q):
        r1 = PederesenCommitmentsEqual.curve.get_random()
        r2 = PederesenCommitmentsEqual.curve.get_random()
        t1 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(r1, g1), PederesenCommitmentsEqual.curve.scalar_mult(r2, h1))
        t2 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(r1, g2), PederesenCommitmentsEqual.curve.scalar_mult(r2, h2))
        c = PederesenCommitmentsEqual.curve.hash_points( [ g1, h1, g2, h2, P, Q, t1, t2 ] )
        s1 = ((r1 + c * self._x) % PederesenCommitmentsEqual.curve.order )
        s2 = ((r2 + c * self._y) % PederesenCommitmentsEqual.curve.order )
        return (t1, s1), (t2, s2)
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        lhs1 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(s1, g1), PederesenCommitmentsEqual.curve.scalar_mult(s2, h1))
        lhs2 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(s1, g2), PederesenCommitmentsEqual.curve.scalar_mult(s2, h2))
        c = PederesenCommitmentsEqual.curve.hash_points([g1, h1, g2, h2, P, Q, t1, t2])
        rhs1 = PederesenCommitmentsEqual.curve.point_add(t1 , PederesenCommitmentsEqual.curve.scalar_mult(c, P))
        rhs2 = PederesenCommitmentsEqual.curve.point_add(t2 , PederesenCommitmentsEqual.curve.scalar_mult(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)