import random 
import hashlib
from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocol, ZeroKnowledgeProtocolNonInteractive
from .zkp_base import Base

class PedersenCommitmentsEqualInteractive(ZeroKnowledgeProtocol):
    def __init__(self, p, x=None, y=None):
        self._x = x
        self._y = y
        self.p = p  # Large prime number for modulo operations
    
    def _mod_exp(self, base, exponent):
        """Performs modular exponentiation."""
        return pow(base, exponent, self.p)

    def challenge(self):
        """Verifier generates and sends a random challenge to the prover."""
        self._c = random.randint(1, self.p - 1)
        return self._c

    def response(self, g1, h1, g2, h2, c):
        """Prover computes the response to the challenge."""
        r1 = random.randint(1, self.p - 1)
        r2 = random.randint(1, self.p - 1)
        
        t1 = (self._mod_exp(g1, r1) * self._mod_exp(h1, r2)) % self.p
        t2 = (self._mod_exp(g2, r1) * self._mod_exp(h2, r2)) % self.p
        
        s1 = (r1 + c * self._x) % (self.p - 1)
        s2 = (r2 + c * self._y) % (self.p - 1)
        
        return (t1, s1), (t2, s2)

    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        """Verifier checks the prover's response against the given challenge."""
        lhs1 = (self._mod_exp(g1, s1) * self._mod_exp(h1, s2)) % self.p
        lhs2 = (self._mod_exp(g2, s1) * self._mod_exp(h2, s2)) % self.p
        rhs1 = (t1 * self._mod_exp(P, self._c)) % self.p
        rhs2 = (t2 * self._mod_exp(Q, self._c)) % self.p
        assert lhs1 == rhs1 
        assert lhs2 == rhs2

class PedersenCommitmentsEqual(ZeroKnowledgeProtocolNonInteractive, Base):

    def __init__(self, p, x=None, y=None):
        self._x = x
        self._y = y
        self.p = p  # Large prime number for modulo operations
    
    def _mod_exp(self, base, exponent):
        """Performs modular exponentiation."""
        return pow(base, exponent, self.p)
    
    def response(self, g1, h1, g2, h2, P, Q):
        
        r1 = random.randint(1, self.p - 1)
        r2 = random.randint(1, self.p - 1)
        
        t1 = (self._mod_exp(g1, r1) * self._mod_exp(h1, r2)) % self.p 
        t2 = (self._mod_exp(g2, r1) * self._mod_exp(h2, r2)) % self.p
        
        c = self._hash([g1, h1, g2, h2, P, Q, t1, t2]) % self.p
        
        s1 = (r1 + c * self._x) % ( self.p - 1)
        s2 = (r2 + c * self._y) % ( self.p - 1)
        
        return (t1, s1), (t2, s2)
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        
        lhs1 = (self._mod_exp(g1, s1) * self._mod_exp(h1, s2)) % self.p
        lhs2 = (self._mod_exp(g2, s1) * self._mod_exp(h2, s2)) % self.p
        
        c = self._hash([g1, h1, g2, h2, P, Q, t1, t2]) % self.p
        
        rhs1 = (t1 * self._mod_exp(P, c)) % self.p
        rhs2 = (t2 * self._mod_exp(Q, c)) % self.p
        
        assert (lhs1 == rhs1) 
        assert (lhs2 == rhs2)

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