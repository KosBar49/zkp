from ecc import generator, randint, Curve
import hashlib
import utime

class PederesenCommitmentsEqualEcc():
    
    def __init__(self, x = None, y = None) -> None:
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
            
    def response(self, g1, h1, g2, h2, P, Q):

        print(".")
        r1 = randint(self.curve.order)
        print(".")
        r2 = randint(self.curve.order)
        print(".")
        t1 = (r1 * g1)
        print('.')
        t1 += (r2 * h1)
        print(".")
        t2 = (r1 * g2)
        print(".")
        t2 += (r2 * h2)
        print(".")
        c = self.hash_points( [ g1, h1, g2, h2, P, Q, t1, t2 ] )
        print(".")
        s1 = ((r1 + c * self._x) % self.curve.order )
        print(".")
        s2 = ((r2 + c * self._y) % self.curve.order )
        print(".")
        return (t1, s1), (t2, s2)
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2):
        print(".")
        (t1, s1) = t1s1
        print(".")
        (t2, s2) = t2s2
        print(".")
        lhs1 = ( s1 * g1)
        print(".")
        lhs1 += ( s2 * h1)
        print(".")
        lhs2 = (s1 * g2)
        print(".")
        lhs2 += (s2 * h2)
        print(".")
        c = self.hash_points([g1, h1, g2, h2, P, Q, t1, t2])
        print(".")
        rhs1 = t1 + (c * P)
        print(".")
        rhs2 = t2 + (c * Q)
        print(".")
        assert (lhs1 == rhs1) and (lhs2 == rhs2)

if __name__ == "__main__":
    
    
    x = 5
    y = 7
    z = 9
    
    client_b = PederesenCommitmentsEqualEcc()
    g, h, g2, h2 = client_b.get_generators(4)
    
    P = ( x  * g ) + ( y * h )
    Q = ( x * g2 ) + ( y * h2)
    
    client_a = PederesenCommitmentsEqualEcc(x, y)
    
    start_response= utime.ticks_us()

    (t1, s1), (t2, s2) = client_a.response(g, h, g2, h2, P, Q)
    
    end_response = utime.ticks_us()

    client_b.verify(g, h, g2, h2, P, Q, (t1, s1), (t2, s2))
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )