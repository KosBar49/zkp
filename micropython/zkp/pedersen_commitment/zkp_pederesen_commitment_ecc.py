from _crypto import ECC
import random
import hashlib
import utime

class PedersenCommitmentEcc():

    curve = ECC.Curve(
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        -0x3,
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    )

    def __init__(self, x=None, y=None) -> None:
        if x and y:
            self._x = x
            self._y = y
            
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
            s = self.randint(0, PedersenCommitmentEcc.curve.q - 1)
            gs.append( s * PedersenCommitmentEcc.curve.G )
            
        return gs

    def response(self, g, h, P):
        
        q = PedersenCommitmentEcc.curve.q
        r1 = self.randint(0, q - 1)
        r2 = self.randint(0, q - 1)

        t = (r1 * g) + (r2 * h)
        c = self.hash_points([g, h, P, t])
        s1 = ((r1 + c * self._x) % q)
        s2 = ((r2 + c * self._y) % q)
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
        lhs = (s1 * g) + (s2 * h)
        c = self.hash_points([g, h, P, t])
        rhs = t + (c * P)
        assert (lhs == rhs)

if __name__ == "__main__":
    
    g = 2
    h = 3
    x = 5
    y = 7
    p = 1019
    
    client_a = PedersenCommitmentEcc(x, y)
    client_b = PedersenCommitmentEcc()
    g, h = client_b.get_generators(2)
    
    P = (x * g) + (y * h)
    
    start_response = utime.ticks_us()
        
    (t, s1, s2) = client_a.response(g, h, P)
    
    end_response = utime.ticks_us()
    
    client_b.verify(g, h, P, t, s1, s2)
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )