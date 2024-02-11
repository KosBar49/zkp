from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocolNonInteractive
import random
import hashlib

class PederesenCommitmentsEqual:

    def __init__(self, p, g, h, x = None, y = None, z = None):
        self._p = p  # Large prime
        self._g = g  # Generator g
        self._h = h  # Generator h
        if x and y and z:
            self._x = x
            self._y = y
            self._z = z

    def hash_points(self, points):
        hash_input = ''.join(str(point) for point in points).encode()
        hash_output = hashlib.sha256(hash_input).hexdigest()
        return int(hash_output, 16) % self._p

    def response(self, P, Q):
        r1 = random.randint(1, self._p - 1)
        r2 = random.randint(1, self._p - 1)
        r3 = random.randint(1, self._p - 1)
        
        # Generate temporary commitments
        t1 = (pow(self._g, r1, self._p) * pow(self._h, r2, self._p)) % ( self._p )
        t2 = (pow(self._g, r1, self._p) * pow(self._h, r3, self._p)) % ( self._p )
        
        # Hash to generate challenge
        c = self.hash_points([P, Q, t1, t2])
        
        # Calculate responses
        s1 = (r1 + c * self._x) % (self._p -1 )
        s2 = (r2 + c * self._y) % (self._p -1 )
        s3 = (r3 + c * self._z) % (self._p -1 )
        
        return (t1, s1), (t2, s2), s3

    def verify(self, P, Q, t1s1, t2s2, s3):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        
        # Re-hash to generate challenge for verification
        c = self.hash_points([P, Q, t1, t2])
        
        # Reconstruct lhs using the responses and original generators
        lhs1 = (pow(self._g, s1, self._p) * pow(self._h, s2, self._p)) % self._p
        lhs2 = (pow(self._g, s1, self._p) * pow(self._h, s3, self._p)) % self._p
        
        # Correctly reconstruct rhs by incorporating the challenge and commitments
        rhs1 = (t1 * pow(P, c, self._p)) % self._p
        rhs2 = (t2 * pow(Q, c, self._p)) % self._p
        print(rhs1)
        print(lhs2)
        # Assertions to verify the commitments
        assert lhs1 == rhs1, "Proof failed for lhs1 and rhs1 comparison."
        assert lhs2 == rhs2, "Proof failed for lhs2 and rhs2 comparison."

class PederesenCommitmentsEqualMessagesEcc(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    def __init__(self, x = None, y = None, z = None) -> None:
        if x and y and z:
            self._x = x
            self._y = y
            self._z = z
    
    def response(self, g1, h1, g2, h2, P, Q):
        r1 = PederesenCommitmentsEqualMessagesEcc.curve.get_random()
        r2 = PederesenCommitmentsEqualMessagesEcc.curve.get_random()
        r3 = PederesenCommitmentsEqualMessagesEcc.curve.get_random()
        
        t1 = PederesenCommitmentsEqualMessagesEcc.curve.point_add(PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(r1, g1), PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(r2, h1))
        t2 = PederesenCommitmentsEqualMessagesEcc.curve.point_add(PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(r1, g2), PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(r3, h2))
        
        c = PederesenCommitmentsEqualMessagesEcc.curve.hash_points( [ g1, h1, g2, h2, P, Q, t1, t2 ] )
        
        s1 = ((r1 + c * self._x) % PederesenCommitmentsEqualMessagesEcc.curve.order )
        s2 = ((r2 + c * self._y) % PederesenCommitmentsEqualMessagesEcc.curve.order )
        s3 = ((r3 + c * self._z) % PederesenCommitmentsEqualMessagesEcc.curve.order )
        return (t1, s1), (t2, s2), s3
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2, s3):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        lhs1 = PederesenCommitmentsEqualMessagesEcc.curve.point_add(PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(s1, g1), PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(s2, h1))
        lhs2 = PederesenCommitmentsEqualMessagesEcc.curve.point_add(PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(s1, g2), PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(s3, h2))
        c = PederesenCommitmentsEqualMessagesEcc.curve.hash_points([g1, h1, g2, h2, P, Q, t1, t2])
        rhs1 = PederesenCommitmentsEqualMessagesEcc.curve.point_add(t1 , PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(c, P))
        rhs2 = PederesenCommitmentsEqualMessagesEcc.curve.point_add(t2 , PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)