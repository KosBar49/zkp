from ecc import generator, randint, Curve
import hashlib
import utime


class PederesenCommitmentsEqualMessagesEcc():
    
    def __init__(self, x = None, y = None, z = None) -> None:
        self.curve = Curve.p256()
        if x and y and z:
            self._x = x
            self._y = y
            self._z = z
            
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
        r3 = randint(self.curve.order)
        print(".")
        t_1 = (r1 * g1)
        print('.')
        t1_ = (r2 * h1)
        print('.')
        t1 = t_1 + t1_
        print(".")
        t_2 = (r1 * g2)
        print(".")
        t2_ = (r3 * h2)
        print(".")
        t2 = t_2 + t2_
        print(".")
        c = self.hash_points( [ g1, h1, g2, h2, P, Q, t1, t2 ] )
        print(".")
        s1 = ((r1 + c * self._x) % self.curve.order )
        print(".")
        s2 = ((r2 + c * self._y) % self.curve.order )
        print(".")
        s3 = ((r3 + c * self._z) % self.curve.order )
        print(".")
        return (t1, s1), (t2, s2), s3
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2, s3):
        print(".")
        (t1, s1) = t1s1
        print(".")
        (t2, s2) = t2s2
        print(".")
        lhs1_ = (s1 * g1)
        print('.')
        lhs_1 = (s2 * h1)
        print('.')
        lhs1 = lhs1_ + lhs_1
        print(".")
        lhs2_ = (s1 * g2)
        print('.')
        lhs_2 = (s3 * h2)
        print('.')
        lhs2 = lhs2_ + lhs_2
        print(".")
        c = self.hash_points([g1, h1, g2, h2, P, Q, t1, t2])
        print(".")
        rhs1 = t1 + (c * P)
        print(".")
        rhs2 = t2 + (c * Q)
        print(".")
        assert lhs1 == rhs1 and lhs2 == rhs2

if __name__ == "__main__":
    
    x = 5
    y = 7
    z = 9
    p = 1019
    
    client_b = PederesenCommitmentsEqualMessagesEcc()
    g1, h1, g2, h2 = client_b.get_generators(4)
    
    P = (x * g1) + (y * h1)
    Q = (x * g2) + (z * h2)
    
    client_a = PederesenCommitmentsEqualMessagesEcc(x, y, z)
    
    start_response= utime.ticks_us()
    
    (t1, s1), (t2, s2), s3 = client_a.response(g1, h1, g2, h2, P, Q)
    
    end_response = utime.ticks_us()

    client_b.verify(g1, h1, g2, h2, P, Q, (t1, s1), (t2, s2), s3)
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )