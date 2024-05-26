from _crypto import ECC
import random
import hashlib
import utime

class DiscreteLogEcc():

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
        Initializes the object with an optional value for x.
        Parameters:
            x (optional): An optional value for x.
        Returns:
            None
        """
        self._random = random
        if x:
            self._x = x
            DiscreteLogEcc.y = self._x * DiscreteLogEcc.curve.G
            
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

    def response(self):
        """
        Generate a response using the DiscreteLogNonInteractiveEcc algorithm.

        Returns:
            tuple: A tuple containing the calculated values t and s.
                - t (Point): The calculated point t.
                - s (int): The calculated value s.
        """
        r = self.randint(0, DiscreteLogEcc.curve.q - 1)
        t = r * DiscreteLogEcc.curve.G
        c = self.hash_points(
            [DiscreteLogEcc.curve.G, DiscreteLogEcc.y, t])
        s = ((r + c * self._x) % DiscreteLogEcc.curve.q)
        return t, s

    def verify(self, s, t):
        """
        Verify the equality of two values by performing a discrete logarithm non-interactive elliptic curve cryptography (ECC) verification.

        Args:
            t: The first value to be verified.
            s: The second value to be verified.

        Returns:
            None

        Raises:
            AssertionError: If the verification fails (i.e., the values are not equal).
        """
        c = self.hash_points(
            [DiscreteLogEcc.curve.G, DiscreteLogEcc.y, t])
        lhs = s * DiscreteLogEcc.curve.G
        yc = c * DiscreteLogEcc.y
        rhs = t + yc
        assert lhs == rhs

if __name__ == "__main__":
    
    start = utime.ticks_ms()
    client_a = DiscreteLogEcc(5)
    client_b = DiscreteLogEcc()
    
    start_response = utime.ticks_us()
    
    (t, s) = client_a.response()
    
    end_response = utime.ticks_us()

    client_b.verify(s, t)
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )