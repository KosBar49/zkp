from _crypto import ECC
import random
import hashlib
import utime


class PederesenCommitmentsEqualMessagesEcc():
    
    curve = ECC.Curve(
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        -0x3,
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    )
    
    def __init__(self, x = None, y = None, z = None) -> None:
        if x and y and z:
            self._x = x
            self._y = y
            self._z = z
            
    def hash_list(self, list_):
        hash = hashlib.sha256()
        for item in list_:
            hash.update(item)
        return int(hash.digest().hex(), 16)

    def hash_points(self, points):
        return self.hash_list([str(point).encode() for point in points])
    
    def randint(self, a, b):
        if a >= 0 and b >= 0:
            if b - a < 2**31:
                return random.randint(a, b)
            else:
                high = (b - a) // (2**31 - 1) + 1
                low = (b - a) % (2**31 - 1)
                return a + high * random.randint(0, (2**31 - 1) - 1) + random.randint(0, low)
        else:
            raise ValueError("Both a and b must be non-negative")
        
    def get_generators(self, n):

        gs = []
        
        for _ in range(n):
            s = self.randint(0, PederesenCommitmentsEqualMessagesEcc.curve.q - 1)
            gs.append( s * PederesenCommitmentsEqualMessagesEcc.curve.G )
            
        return gs
    
    def response(self, g1, h1, g2, h2, P, Q):
        
        q = PederesenCommitmentsEqualMessagesEcc.curve.q
        
        r1 = self.randint(0, q - 1)
        r2 = self.randint(0, q - 1)
        r3 = self.randint(0, q - 1)
        
        t1 = (r1 * g1) + (r2 * h1)
        t2 = (r1 * g2) + (r3 * h2)
        
        c = self.hash_points( [ g1, h1, g2, h2, P, Q, t1, t2 ] )
        
        s1 = ((r1 + c * self._x) % q )
        s2 = ((r2 + c * self._y) % q )
        s3 = ((r3 + c * self._z) % q )
        
        return (t1, s1), (t2, s2), s3
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2, s3):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        
        lhs1 = (s1 * g1) + (s2 * h1)
        lhs2 = (s1 * g2) + (s3 * h2)
        
        c = self.hash_points([g1, h1, g2, h2, P, Q, t1, t2])
        
        rhs1 = t1 + (c * P)
        rhs2 = t2 + (c * Q)
        
        assert lhs1 == rhs1 and lhs2 == rhs2

if __name__ == "__main__":
    
    x = 5
    y = 7
    z = 9
    p = 1019
    
    client_b = PederesenCommitmentsEqualMessagesEcc()
    g1, h1, g2, h2 = client_b.get_generators(4)
    
    P = (x * g1) + (y * h1)
    Q = (x * g2) + (z * h2)
    
    client_a = PederesenCommitmentsEqualMessagesEcc(x, y, z)
    
    start_response= utime.ticks_us()
    
    (t1, s1), (t2, s2), s3 = client_a.response(g1, h1, g2, h2, P, Q)
    
    end_response = utime.ticks_us()

    client_b.verify(g1, h1, g2, h2, P, Q, (t1, s1), (t2, s2), s3)
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )