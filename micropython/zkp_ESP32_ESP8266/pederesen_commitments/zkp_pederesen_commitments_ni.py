import random
import hashlib
import utime

class PedersenCommitmentsEqual():

    def __init__(self, p, x=None, y=None):
        self._x = x
        self._y = y
        self.p = p  # Large prime number for modulo operations
        
    def _hash(self, itmes):
        s_ = ''
        h = hashlib.sha256()
        for item in itmes:      
            s_ += str(item)
        h.update(s_.encode())
        return int(h.digest().hex(), 16)
    
    def _mod_exp(self, base, exponent):
        """Performs modular exponentiation."""
        return pow(base, exponent, self.p)
    
    def response(self, g1, h1, g2, h2, P, Q):
        
        r1 = random.randint(2, self.p )
        r2 = random.randint(2, self.p )
        
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


if __name__ == "__main__":
    
    x = 5
    y = 7
    z = 9
    
    p = 1019
    
    g = 2
    g2 = 5
    h = 3
    h2 = 7

    P = (pow(g, x, p) * pow(h, y, p)) % p
    Q = (pow(g2, x, p) * pow(h2, y, p)) % p   
    
    client_a = PedersenCommitmentsEqual(p, x, y)
    client_b = PedersenCommitmentsEqual(p)
    
    start_response= utime.ticks_us()
    
    (t1, s1), (t2, s2) = client_a.response(g, h, g2, h2, P, Q)
    
    end_response = utime.ticks_us()

    client_b.verify(g, h, g2, h2, P, Q, (t1, s1), (t2, s2))
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )