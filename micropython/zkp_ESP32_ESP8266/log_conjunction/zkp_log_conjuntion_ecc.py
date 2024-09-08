from ecc import generator, randint, Curve
import hashlib
import utime
import gc 

class DiscreteLogConjunctionEcc():

    def __init__(self, x=None, y=None):
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
            print(".")
            gs.append( generator() * s )
            
        return gs

    def response(self, g, h, P, Q):
        
        r1 = randint(self.curve.order)
        r2 = randint(self.curve.order)
        
        print(".")
        t1 = g * r1
        print(".")
        t2 = h * r2
        print(".")
    
        c = self.hash_points([g, h, P, Q, t1, t2])
        
        s1 = ((r1 + c * self._x) % self.curve.order)
        s2 = ((r2 + c * self._y) % self.curve.order)
        
        return (t1, s1), (t2, s2)

    def verify(self, g, h, P, Q, t1s1, t2s2):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        c = self.hash_points([g, h, P, Q, t1, t2])
        print(".")
        
        lhs1 = s1 * g
        print(".")
        rhs1 = t1 + (c * P)
        print(".")
        lhs2 = s2 * h
        print(".")
        rhs2 = t2 + (c * Q)
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
    
if __name__ == "__main__":
        
    x = 2 
    y = 3
    
    client_a = DiscreteLogConjunctionEcc(x, y)
    g, h = client_a.get_generators(2)
    
    P = g * x
    Q = h * y
    
    start_response = utime.ticks_us()
    (t1, s1), (t2, s2) = client_a.response(g, h, P, Q)
    
    end_response = utime.ticks_us()
    
    client_a.verify(g, h, P, Q, (t1, s1), (t2, s2))
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )