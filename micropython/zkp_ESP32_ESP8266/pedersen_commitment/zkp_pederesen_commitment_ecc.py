from ecc import generator, randint, Curve
import hashlib
import utime

class PedersenCommitmentEcc():

    def __init__(self, x=None, y=None) -> None:
        self.curve = Curve.p256() #P256
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
        
    def get_generators(self, n):

        gs = []
        
        for _ in range(n):
            
            s = randint( self.curve.order )
            print(s)
            gs.append( generator() * s )
            
        return gs

    def response(self, g, h, P):
        print('.')
        r1 = randint(self.curve.order)
        print('.')
        r2 = randint(self.curve.order)
        print('.')
        t = (r1 * g)
        print('.')
        t += (r2 * h)
        print('.')
        c = self.hash_points([g, h, P, t])
        print('.')
        s1 = ((r1 + c * self._x) % self.curve.order)
        print('.')
        s2 = ((r2 + c * self._y) % self.curve.order)
        print('.')
        return t, s1, s2

    def verify(self, g, h, P, t, s1, s2):
        lhs = (s1 * g)
        print('.')
        lhs += (s2 * h)
        print('.')
        c = self.hash_points([g, h, P, t])
        print('.')
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