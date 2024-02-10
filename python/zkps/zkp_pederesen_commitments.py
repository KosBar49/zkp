from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocolNonInteractive
import random
import hashlib

class PederesenCommitmentsEqual(ZeroKnowledgeProtocolNonInteractive):

    def __init__(self, p, g, h, x=None):
        self._p = p  # Large prime
        self._g = g  # Generator g
        self._h = h  # Generator h
        self._x = x  # Secret x, if known

    def hash_points(self, points):
        """Hashes points into a scalar value."""
        hash_input = ''.join(str(point) for point in points).encode()
        hash_output = hashlib.sha256(hash_input).hexdigest()
        return int(hash_output, 16) % self._p

    def response(self, P, Q):
        
        """Generates a response for the given commitments P and Q."""
        r1 = random.randint(1, self._p - 1)
        r2 = random.randint(1, self._p - 1)
        r3 = random.randint(1, self._p - 1)
        
        # Temporarily commitments
        t1 = (pow(self._g, r1, self._p) * pow(self._h, r2, self._p)) % self._p
        t2 = (pow(self._g, r1, self._p) * pow(self._h, r3, self._p)) % self._p
        
        c = self.hash_points([P, Q, t1, t2])
        
        s1 = (r1 + c * self._x) % self._p
        s2 = (r2 + c * self._x) % self._p
        s3 = (r3 + c * self._x) % self._p
        
        return (t1, s1), (t2, s2), s3

    def verify(self, P, Q, t1s1, t2s2, s3):
        """Verifies the response for the commitments P and Q."""
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        
        c = self.hash_points([P, Q, t1, t2])
        
        lhs1 = (pow(self._g, s1, self._p) * pow(self._h, s2, self._p)) % self._p
        lhs2 = (pow(self._g, s1, self._p) * pow(self._h, s3, self._p)) % self._p
        
        rhs1 = (t1 * pow(P, c, self._p)) % self._p
        rhs2 = (t2 * pow(Q, c, self._p)) % self._p
        
        assert lhs1 == rhs1 and lhs2 == rhs2, "Proof failed"

class PederesenCommitmentsEqualEcc(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None, y = None) -> None:
        if x and y:
            self._x = x
            self._y = y
            
    def response(self, g1, h1, g2, h2, P, Q):
        r1 = PederesenCommitmentsEqualEcc.curve.get_random()
        r2 = PederesenCommitmentsEqualEcc.curve.get_random()
        t1 = PederesenCommitmentsEqualEcc.curve.point_add(PederesenCommitmentsEqualEcc.curve.scalar_mult(r1, g1), PederesenCommitmentsEqualEcc.curve.scalar_mult(r2, h1))
        t2 = PederesenCommitmentsEqualEcc.curve.point_add(PederesenCommitmentsEqualEcc.curve.scalar_mult(r1, g2), PederesenCommitmentsEqualEcc.curve.scalar_mult(r2, h2))
        c = PederesenCommitmentsEqualEcc.curve.hash_points( [ g1, h1, g2, h2, P, Q, t1, t2 ] )
        s1 = ((r1 + c * self._x) % PederesenCommitmentsEqualEcc.curve.order )
        s2 = ((r2 + c * self._y) % PederesenCommitmentsEqualEcc.curve.order )
        return (t1, s1), (t2, s2)
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        lhs1 = PederesenCommitmentsEqualEcc.curve.point_add(PederesenCommitmentsEqualEcc.curve.scalar_mult(s1, g1), PederesenCommitmentsEqualEcc.curve.scalar_mult(s2, h1))
        lhs2 = PederesenCommitmentsEqualEcc.curve.point_add(PederesenCommitmentsEqualEcc.curve.scalar_mult(s1, g2), PederesenCommitmentsEqualEcc.curve.scalar_mult(s2, h2))
        c = PederesenCommitmentsEqualEcc.curve.hash_points([g1, h1, g2, h2, P, Q, t1, t2])
        rhs1 = PederesenCommitmentsEqualEcc.curve.point_add(t1 , PederesenCommitmentsEqualEcc.curve.scalar_mult(c, P))
        rhs2 = PederesenCommitmentsEqualEcc.curve.point_add(t2 , PederesenCommitmentsEqualEcc.curve.scalar_mult(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)