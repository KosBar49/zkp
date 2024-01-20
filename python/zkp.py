import random
import hashlib
from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocolNonInteractive   

class DiscreteLogDisjunction(ZeroKnowledgeProtocolNonInteractive):

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

    def response(self):
        r1 = random.randint(0, self._p - 1)
        c2 = random.randint(0, self._p - 1)
        s2 = random.randint(0, self._p - 1)

        t1 = pow(self._g, r1, self._p)
        t2 = (pow(self._h, s2, self._p) * pow(self._Q, (0 - c2), self._p)) % self._p

        cha1 = str(self._g) + str(self._h) + str(self._P) + str(self._Q) + str(t1) + str(t2)
        hash_ = hashlib.md5()
        hash_.update(cha1.encode())
        c = int(hash_.hexdigest(), 16) % self._p

        c1 = (c - c2) % self._p 

        s1 = ( r1 + c1 * self._x ) % (self._p - 1)

        return (t1, c1, s1), (t2, c2, s2)

    def verify(self, g, h, P, Q, t1c1s1, t2c2s2):
        (t1, c1, s1) = t1c1s1
        (t2, c2, s2) = t2c2s2

        cha1 = str(g) + str(h) + str(P) + str(Q) + str(t1) + str(t2)
        hash_ = hashlib.md5()
        hash_.update(cha1.encode())
        c = int(hash_.hexdigest(), 16) % self._p

        assert (c == (c1 + c2) % self._p )

        lhs1 = pow(g, s1, self._p)
        rhs1 = (t1 * pow(P, c1, self._p)) % self._p

        lhs2 = pow(h, s2, self._p)
        rhs2 = (t2 * pow(Q, c2, self._p)) % self._p
        print(rhs1)
        print(lhs1)
        print(rhs2)
        print(lhs2)

        assert lhs1 == rhs1 and lhs2 == rhs2
        
class DiscreteLogDisjunctionEcc(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None):
        if x:
            self._x = x
            
    def response(self, g, h, P, Q):
        
        r1 = DiscreteLogDisjunctionEcc.curve.get_random()
        c2 = DiscreteLogDisjunctionEcc.curve.get_random()
        s2 = DiscreteLogDisjunctionEcc.curve.get_random()
        
        t1 = DiscreteLogDisjunctionEcc.curve.scalar_mult(r1, g)
        t2 = DiscreteLogDisjunctionEcc.curve.point_add(DiscreteLogDisjunctionEcc.curve.scalar_mult(s2, h), DiscreteLogDisjunctionEcc.curve.scalar_mult( (0-c2) % DiscreteLogDisjunctionEcc.curve.order , Q))
        c = DiscreteLogDisjunctionEcc.curve.hash_points( [ g, h, P, Q, t1, t2 ] )
        c1 = (c - c2) % DiscreteLogDisjunctionEcc.curve.order
        s1 = ((r1 + c1 * self._x) % DiscreteLogDisjunctionEcc.curve.order  ) % DiscreteLogDisjunctionEcc.curve.order 
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
        c = DiscreteLogDisjunctionEcc.curve.hash_points( [ g, h, P, Q, t1, t2 ] )
        assert (c == (c1 + c2) % DiscreteLogDisjunctionEcc.curve.order )
        lhs1 = DiscreteLogDisjunctionEcc.curve.scalar_mult(s1, g)
        rhs1 = DiscreteLogDisjunctionEcc.curve.point_add(t1, DiscreteLogDisjunctionEcc.curve.scalar_mult(c1, P))
        lhs2 = DiscreteLogDisjunctionEcc.curve.scalar_mult(s2, h)
        rhs2 = DiscreteLogDisjunctionEcc.curve.point_add(t2, DiscreteLogDisjunctionEcc.curve.scalar_mult(c2, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
        
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
