import utime
import random
import hashlib


class DiscreteLogConjunction():

    def __init__(self, g, h, P, Q, p, x=None, y=None):
        """
        Initialize the protocol parameters.
        :param g, h: Generators of the group.
        :param P, Q: Public values such that P = g^a and Q = h^b.
        :param p: Prime modulus.
        :param x: Secret value.
        """
        self._g = g
        self._h = h
        self._P = P
        self._Q = Q
        self._p = p
        self._x = x
        self._y = y
        self._random = random
        
    def _hash(self, itmes):
        s_ = ''
        h = hashlib.sha256()
        for item in itmes:      
            s_ += str(item)
        h.update(s_.encode())
        return int(h.digest().hex(), 16)

    def response(self):
        r1 = self._random.randint(0, self._p - 1)
        r2 = self._random.randint(0, self._p - 1)

        t1 = pow(self._g, r1, self._p)
        t2 = pow(self._h, r2, self._p)

        c = self._hash([self._g, self._h, self._P, self._Q, t1, t2]) % self._p
        
        s1 = (r1 + c * self._x) % (self._p - 1)
        s2 = (r2 + c * self._y) % (self._p - 1)

        return (t1, s1), (t2, s2)

    def verify(self, t1cs1, t2cs2):

        (t1, s1) = t1cs1
        (t2, s2) = t2cs2

        c = self._hash([self._g, self._h, self._P, self._Q, t1, t2]) % self._p
        
        lhs1 = pow(self._g, s1, self._p)
        rhs1 = (t1 * pow(self._P, c, self._p)) % self._p

        lhs2 = pow(self._h, s2, self._p)
        rhs2 = (t2 * pow(self._Q, c, self._p)) % self._p

        assert lhs1 == rhs1
        assert lhs2 == rhs2

if __name__ == "__main__":
    print('starting...')
    #generators 
    g = 2 
    h = 3
    # secrets
    x = 3
    y = 5 
    
    P = g ** x
    Q = h ** y 
    p = 5
    
    client_a = DiscreteLogConjunction(g, h, P, Q, p, x, y)
    client_b = DiscreteLogConjunction(g, h, P, Q, p) 
    
    start = utime.ticks_us()
    
    (t1, s1), (t2, s2) = client_a.response()
    client_b.verify((t1, s1), (t2, s2))
    
    end = utime.ticks_us()
    duration = (end - start) 
    
    print( f"time: {duration:.3f}" )