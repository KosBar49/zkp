import random
import hashlib
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
        
class PederesenCommitmentEqual(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None, y = None) -> None:
        if x and y:
            self._x = x
            self._y = y
            
    def response(self, g1, h1, g2, h2, P, Q):
        r1 = PederesenCommitmentEqual.curve.get_random()
        r2 = PederesenCommitmentEqual.curve.get_random()
        t1 = PederesenCommitmentEqual.curve.point_add(PederesenCommitmentEqual.curve.scalar_mult(r1, g1), PederesenCommitmentEqual.curve.scalar_mult(r2, h1))
        t2 = PederesenCommitmentEqual.curve.point_add(PederesenCommitmentEqual.curve.scalar_mult(r1, g2), PederesenCommitmentEqual.curve.scalar_mult(r2, h2))
        c = PederesenCommitmentEqual.curve.hash_points( [ g1, h1, g2, h2, P, Q, t1, t2 ] )
        s1 = ((r1 + c * self._x) % PederesenCommitmentEqual.curve.order )
        s2 = ((r2 + c * self._y) % PederesenCommitmentEqual.curve.order )
        return (t1, s1), (t2, s2)
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        lhs1 = PederesenCommitmentEqual.curve.point_add(PederesenCommitmentEqual.curve.scalar_mult(s1, g1), PederesenCommitmentEqual.curve.scalar_mult(s2, h1))
        lhs2 = PederesenCommitmentEqual.curve.point_add(PederesenCommitmentEqual.curve.scalar_mult(s1, g2), PederesenCommitmentEqual.curve.scalar_mult(s2, h2))
        c = PederesenCommitmentEqual.curve.hash_points([g1, h1, g2, h2, P, Q, t1, t2])
        rhs1 = PederesenCommitmentEqual.curve.point_add(t1 , PederesenCommitmentEqual.curve.scalar_mult(c, P))
        rhs2 = PederesenCommitmentEqual.curve.point_add(t2 , PederesenCommitmentEqual.curve.scalar_mult(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
        
class PederesenCommitmentsEqual(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    def __init__(self, x = None, y = None, z = None) -> None:
        if x and y and z:
            self._x = x
            self._y = y
            self._z = z
    
    def response(self, g1, h1, g2, h2, P, Q):
        r1 = PederesenCommitmentsEqual.curve.get_random()
        r2 = PederesenCommitmentsEqual.curve.get_random()
        r3 = PederesenCommitmentsEqual.curve.get_random()
        
        t1 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(r1, g1), PederesenCommitmentsEqual.curve.scalar_mult(r2, h1))
        t2 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(r1, g2), PederesenCommitmentsEqual.curve.scalar_mult(r3, h2))
        
        c = PederesenCommitmentsEqual.curve.hash_points( [ g1, h1, g2, h2, P, Q, t1, t2 ] )
        
        s1 = ((r1 + c * self._x) % PederesenCommitmentsEqual.curve.order )
        s2 = ((r2 + c * self._y) % PederesenCommitmentsEqual.curve.order )
        s3 = ((r3 + c * self._z) % PederesenCommitmentsEqual.curve.order )
        return (t1, s1), (t2, s2), s3
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2, s3):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        lhs1 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(s1, g1), PederesenCommitmentsEqual.curve.scalar_mult(s2, h1))
        lhs2 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(s1, g2), PederesenCommitmentsEqual.curve.scalar_mult(s3, h2))
        c = PederesenCommitmentsEqual.curve.hash_points([g1, h1, g2, h2, P, Q, t1, t2])
        rhs1 = PederesenCommitmentsEqual.curve.point_add(t1 , PederesenCommitmentsEqual.curve.scalar_mult(c, P))
        rhs2 = PederesenCommitmentsEqual.curve.point_add(t2 , PederesenCommitmentsEqual.curve.scalar_mult(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
        
class DiscreteLogInequality(ZeroKnowledgeProtocolNonInteractive): # not working
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None, y = None):
        self._x = x
        self._y = y
        
    def response(self, g, h, P, Q):
        r = DiscreteLogInequality.curve.get_random()
        
        alpha = (self._x * r) % DiscreteLogInequality.curve.order
        beta = (0 - r) % DiscreteLogInequality.curve.order
        
        ar = DiscreteLogInequality.curve.scalar_mult( alpha, h )
        qr = DiscreteLogInequality.curve.scalar_mult( beta, Q )
        
        C = DiscreteLogInequality.curve.point_add(ar, qr)
        print(f"C: {C}")

        iden = DiscreteLogInequality.curve.point_add(C, C)
        print(f"iden: {iden}")
        client = PederesenCommitmentEqual(alpha, beta)
        (t1, s1), (t2, s2) = client.response(g, P, h, Q, iden, C)
        return C, (t1, s1), (t2, s2)
    
    def verify(self, g, h, P, Q, C, t1s1, t2s2 ):
       
       iden = DiscreteLogInequality.curve.point_add(C, C)
       proover = PederesenCommitmentEqual()
       proover.verify(g, P, h, Q, iden, C, t1s1, t2s2)
