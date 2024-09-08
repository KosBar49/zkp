from ecc import generator, randint, Curve
import hashlib
try: 
    import utime
except Exception as e:
    import time as utime

class DiscreteLogDisjunctionEcc():

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
            s = randint(self.curve.order - 1)
            gs.append( s * generator() )
            
        return gs

    def response(self, g, h, P, Q):
        print(".")
        r1 = randint(self.curve.order - 1)
        print(".")
        c2 = randint(self.curve.order - 1)
        print(".")
        s2 = randint(self.curve.order - 1)
        print(".")
        t1 = r1 * g
        print(".")
        s2h = s2 * h
        print(".")
        c2Q = ( ((0-c2) % self.curve.order ) * Q)
        print(".")
        t2 = s2h + c2Q
        print(".")
        c = self.hash_points([g, h, P, Q, t1, t2])
        print(".")
        c1 = (c - c2)
        print(".")
        s1 = ((r1 + c1 * self._x) % self.curve.order) % self.curve.order
        return (t1, c1, s1), (t2, c2, s2)

    def verify(self, g, h, P, Q, t1cs1, t2cs2):
        print(".")
        (t1, c1, s1) = t1cs1
        (t2, c2, s2) = t2cs2
        print(".")
        c = self.hash_points([g, h, P, Q, t1, t2])
        assert (c == (c1 + c2) )
        print(".")
        lhs1 = s1 * g
        print(".")                                                                                                                                                 
        rhs1 = t1 + (c1 * P)
        print(".")       
        lhs2 = s2 * h
        print(".")  
        rhs2 = t2 + (c2 * Q)
        print(".")
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
        
if __name__ == "__main__":
    
    x = 2 
    y = 3
    
    client_a = DiscreteLogDisjunctionEcc(x)
    g, h = client_a.get_generators(2)
    
    P = x * g
    Q = y * h
    
    start_response = utime.ticks_ms()
    
    t1c1s1, t2c2s2 = client_a.response(g, h, P, Q)
    end_response = utime.ticks_us()
    client_a.verify(g, h, P, Q, t1c1s1, t2c2s2)

    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )