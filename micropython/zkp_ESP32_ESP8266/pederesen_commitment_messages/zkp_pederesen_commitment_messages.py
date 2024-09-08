import random
import utime

class PedersenCommitmentsEqualMessagesInteractive():
    def __init__(self, p, g, h, x=None, y=None, z=None):
        self._p = p
        self._g = g
        self._h = h
        if x and y and z:
            self._x = x
            self._y = y
            self._z = z
        self._random = random
            
    def challenge(self):
        self._c = self._random.randint(1, self._p - 1)
        return self._c

    def response(self, c):
        self.r1 = self._random.randint(1, self._p - 1)
        self.r2 = self._random.randint(1, self._p - 1)
        self.r3 = self._random.randint(1, self._p - 1)
        
        t1 = (pow(self._g, self.r1, self._p) * pow(self._h, self.r2, self._p)) % self._p
        t2 = (pow(self._g, self.r1, self._p) * pow(self._h, self.r3, self._p)) % self._p
        
        s1 = (self.r1 + c * self._x) % (self._p - 1)
        s2 = (self.r2 + c * self._y) % (self._p - 1)
        s3 = (self.r3 + c * self._z) % (self._p - 1)
        
        return (t1, s1), (t2, s2), s3 # t1, s1, s2, s3

    def verify(self, P, Q, t1s1, t2s2, s3):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        
        lhs1 = (pow(self._g, s1, self._p) * pow(self._h, s2, self._p)) % self._p
        lhs2 = (pow(self._g, s1, self._p) * pow(self._h, s3, self._p)) % self._p
        
        rhs1 = (t1 * pow(P, self._c, self._p)) % self._p
        rhs2 = (t2 * pow(Q, self._c, self._p)) % self._p

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
    
    
    client_a = PedersenCommitmentsEqualMessagesInteractive(p, g, h, x, y, z)
    client_b = PedersenCommitmentsEqualMessagesInteractive(p, g, h)
    
    start_response = utime.ticks_us()
    c = client_b.challenge()
    t1s1, t2s2, s3 = client_a.response(c)
    end_response = utime.ticks_us()
    client_b.verify(P, Q, t1s1, t2s2, s3)
    
    end_verify = utime.ticks_us()

    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )