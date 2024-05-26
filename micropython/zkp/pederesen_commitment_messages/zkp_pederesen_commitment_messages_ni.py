import hashlib
import random
import utime


class PederesenCommitmentsEqualMessages():
    
    def __init__(self, p, g, h, x = None, y = None, z = None):
        self._p = p
        self._g = g
        self._h = h
        if x and y and z:
            self._x = x
            self._y = y
            self._z = z
        self._random = random
        
    def _hash(self, itmes):
        s_ = ''
        h = hashlib.sha256()
        for item in itmes:      
            s_ += str(item)
        h.update(s_.encode())
        return int(h.digest().hex(), 16)

    def response(self, P, Q):
        r1 = self._random.randint(1, self._p - 1)
        r2 = self._random.randint(1, self._p - 1)
        r3 = self._random.randint(1, self._p - 1)
        
        t1 = (pow(self._g, r1, self._p) * pow(self._h, r2, self._p)) % ( self._p )
        t2 = (pow(self._g, r1, self._p) * pow(self._h, r3, self._p)) % ( self._p )
        
        c = self._hash([P, Q, t1, t2]) % self._p
        
        s1 = (r1 + c * self._x) % (self._p - 1 )
        s2 = (r2 + c * self._y) % (self._p - 1 )
        s3 = (r3 + c * self._z) % (self._p - 1 )
        
        return (t1, s1), (t2, s2), s3

    def verify(self, P, Q, t1s1, t2s2, s3):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        
        c = self._hash([P, Q, t1, t2]) % self._p
        
        lhs1 = (pow(self._g, s1, self._p) * pow(self._h, s2, self._p)) % self._p
        lhs2 = (pow(self._g, s1, self._p) * pow(self._h, s3, self._p)) % self._p
        
        rhs1 = (t1 * pow(P, c, self._p)) % self._p
        rhs2 = (t2 * pow(Q, c, self._p)) % self._p

        assert lhs1 == rhs1 and lhs2 == rhs2
        


if __name__ == "__main__":
    
    g = 2
    h = 3
    x = 5
    y = 7
    z = 9
    p = 1019
    
    P = (pow(g, x, p) * pow(h, y, p)) % p
    Q = (pow(g, x, p) * pow(h, z, p)) % p
    
    client_a = PederesenCommitmentsEqualMessages(p, g, h, x, y, z)
    client_b = PederesenCommitmentsEqualMessages(p, g, h)
    
    start_response = utime.ticks_us()
    t1s1, t2s2, s3 = client_a.response(P, Q)   
    end_response = utime.ticks_us()
    
    client_b.verify(P, Q, t1s1, t2s2, s3)
    
    end_verify = utime.ticks_us()

    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )