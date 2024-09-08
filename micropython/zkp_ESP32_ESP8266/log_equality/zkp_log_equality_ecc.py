from ecc import generator, randint, Curve
import hashlib
import utime

class DiscreteLogEqualityEcc():
    
    def __init__(self, x=None):
        self.curve = Curve.p256()
        if x:
            self._x = x
    
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
            s = randint(self.curve.order)
            gs.append( s * generator() )
            
        return gs

    def response(self, g, h, P, Q):
        print(".") 
        r = randint(self.curve.order)
        print(".") 
        t1 = r * g
        print(".") 
        t2 = r * h
        c = self.hash_points([g, h, P, Q, t1, t2])
        print(".") 
        s = ((r + c * self._x) % self.curve.order)
        return t1, t2, s

    def verify(self, g, h, P, Q, t1, t2, s):
        print(".") 
        c = self.hash_points([g, h, P, Q, t1, t2])
        print(".") 
        lhs1 = s * g
        print(".") 
        rhs1 = t1 + (c * P)
        print(".") 
        lhs2 = s * h
        print(".") 
        rhs2 = t2 + (c * Q)
        print(".") 
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
        
        
if __name__ == "__main__":
    
    x = 2 
    client_b = DiscreteLogEqualityEcc()
    g, h = client_b.get_generators(2)
    P = x * g
    Q = x * h
    client_a = DiscreteLogEqualityEcc(x)
    
    start_response = utime.ticks_us()
    (t1, t2, s) = client_a.response(g, h, P, Q)
    end_response = utime.ticks_us()
    client_b.verify(g, h, P, Q, t1, t2, s)
    
    end_verify = utime.ticks_us()

    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )