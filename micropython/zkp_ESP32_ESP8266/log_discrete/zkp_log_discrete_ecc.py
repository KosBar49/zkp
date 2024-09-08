from ecc import generator, randint, Curve
import hashlib
import utime  

class DiscreteLogEcc():

    def __init__(self, x=None):
        self.curve = Curve.p256()
        if x:
            self._x = x
            self._y = self._x * generator()
            
    def hash_list(self, list_):
        hash = hashlib.sha256()
        for item in list_:
            hash.update(item)
        return int(hash.digest().hex(), 16)

    def hash_points(self, points):
        return self.hash_list([str(point).encode() for point in points])

    def response(self):
        print(".")
        r = randint(self.curve.order)
        print(".")
        t = r * generator()
        c = self.hash_points(
            [generator(), self._y, t])
        s = ((r + c * self._x) % self.curve.order)
        return t, s

    def verify(self, s, t):
        print(".")
        c = self.hash_points(
            [generator(), self._y, t])
        print(".")
        lhs = s * generator()
        print(".")
        yc = c * self._y
        print(".")
        rhs = t + yc
        print(".")
        assert lhs == rhs

if __name__ == "__main__":
    
    start = utime.ticks_ms()
    client_a = DiscreteLogEcc(5)

    start_response = utime.ticks_us()
    
    (t, s) = client_a.response()
    
    end_response = utime.ticks_us()

    client_a.verify(s, t)
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )