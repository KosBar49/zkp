from _crypto import ECC
import random
import hashlib
import utime

class DiscreteLogDisjunctionEcc():

    curve = ECC.Curve(
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        -0x3,
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    )

    def __init__(self, x=None):
        if x:
            self._x = x
            
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
            s = self.randint(0, DiscreteLogDisjunctionEcc.curve.q - 1)
            gs.append( s * DiscreteLogDisjunctionEcc.curve.G )
            
        return gs

    def response(self, g, h, P, Q):

        q = DiscreteLogDisjunctionEcc.curve.q
        r1 = self.randint(0, q - 1)
        c2 = self.randint(0, q - 1)
        s2 = self.randint(0, q - 1)
        
        t1 = r1 * g
        t2 = (s2 * h) + ((-c2 % q ) * Q)
        
        c = self.hash_points([g, h, P, Q, t1, t2])
        
        c1 = (c - c2) % q
        s1 = ((r1 + c1 * self._x) %
              q) % q
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
        c = self.hash_points([g, h, P, Q, t1, t2])
        
        assert (c == (c1 + c2) % DiscreteLogDisjunctionEcc.curve.q)
        
        lhs1 = s1 * g
                                                                                                                                                              
        rhs1 = t1 + (c1 * P)
        lhs2 = s2 * h
        rhs2 = t2 + (c2 * Q)
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
        
if __name__ == "__main__":
    
    x = 2 
    y = 3
    
    client_a = DiscreteLogDisjunctionEcc(x)
    client_b = DiscreteLogDisjunctionEcc()
    g, h = client_b.get_generators(2)
    
    P = x * g
    Q = y * h
    
    start = utime.ticks_ms()
    
    t1c1s1, t2c2s2 = client_a.response(g, h, P, Q)
    client_b.verify(g, h, P, Q, t1c1s1, t2c2s2)

    end = utime.ticks_ms()
    duration = (end - start) 
    print( f"time: {duration:.3f}" )