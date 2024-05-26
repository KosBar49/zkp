from _crypto import ECC
import random
import hashlib
import utime


class DiscreteLogEqualityEcc():

    curve = ECC.Curve(
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        -0x3,
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    )

    def __init__(self, x=None):
        """
        Initializes an instance of the class.

        Parameters:
            x (optional): The value to assign to the private attribute _x.

        Returns:
            None
        """
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
            s = self.randint(0, DiscreteLogEqualityEcc.curve.q - 1)
            gs.append( s * DiscreteLogEqualityEcc.curve.G )
            
        return gs

    def response(self, g, h, P, Q):
        """
        Calculates the response for the given parameters.
        Args:
            g (Point): The base point of the curve.
            h (Point): Another point on the curve.
            P (Point): A point on the curve.
            Q (Point): Another point on the curve.
        Returns:
            Tuple[Point, Point, int]: A tuple containing the calculated points t1 and t2, and the calculated integer s.
        """
        q = DiscreteLogEqualityEcc.curve.q
        r = self.randint(0, q - 1)
        t1 = r * g
        t2 = r * h
        c = self.hash_points([g, h, P, Q, t1, t2])
        s = ((r + c * self._x) % q)
        return t1, t2, s

    def verify(self, g, h, P, Q, t1, t2, s):
        """
        Verify the equality of two discrete logarithms.
        Args:
            g (Point): The base point of the first logarithm.
            h (Point): The base point of the second logarithm.
            P (Point): The first point on the elliptic curve.
            Q (Point): The second point on the elliptic curve.
            t1 (Point): The first temporary point.
            t2 (Point): The second temporary point.
            s (Scalar): The scalar value.
        Returns:
            None
        Raises:
            AssertionError: If the equality of the discrete logarithms is not verified.
        """
        c = self.hash_points([g, h, P, Q, t1, t2])
        lhs1 = s *g
        rhs1 = t1 + (c * P)
        lhs2 = s * h
        rhs2 = t2 + (c * Q)
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
        
        
if __name__ == "__main__":
    
    x = 2 
    client_b = DiscreteLogEqualityEcc()
    g, h = client_b.get_generators(2)
    P = x * g
    Q = x * h
    client_a = DiscreteLogEqualityEcc(x)
    
    start = utime.ticks_ms()
    (t1, t2, s) = client_a.response(g, h, P, Q)
    client_b.verify(g, h, P, Q, t1, t2, s)
    
    end = utime.ticks_ms()
    duration = (end - start) 
    print( f"time: {duration:.3f}" )