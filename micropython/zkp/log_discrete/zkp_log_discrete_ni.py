import random
import hashlib
import utime 

class DiscreteLog():
    """
    Implementation based on https://asecuritysite.com/zero/nizkp2
    """

    def __init__(self, g, y, p, x=None):
        """
        :param g: generator
        :param y: public key
        :param p: modulo
        :param x: secret
        """
        self._g = g
        self._p = p
        self._y = y
        self._x = x
        self._random = random

    def _hash(self, itmes):
        s_ = ''
        h = hashlib.sha256()
        for item in itmes:      
            s_ += str(item)
        h.update(s_.encode())
        return int(h.digest().hex(), 16)
    
    def response(self):
        """
        Calculate the response value based on the current state of the object.
        Returns:
            int: The calculated response value.
        """
        self._v = self._random.randint(0, self._p - 1)
        t = pow(self._g, self._v, self._p)
        self._c = self._hash([self._g, self._y, t])
        return t, (self._v - self._c * self._x) % (self._p - 1)

    def verify(self, s, t):
        """
        Verify the validity of a given signature.
        Parameters:
            r (int): The r value of the signature.
            c (int): The c value of the signature.
            V (int): The V value of the signature.
        Returns:
            None
        Raises:
            AssertionError: If the signature is invalid.
        """        
        c = self._hash([self._g, self._y, t])
        check = (pow(self._g, s, self._p) * pow(self._y, c, self._p)) % self._p
        assert t == check

if __name__ == "__main__":

    g = 2
    x = 3
    P = g ** x
    p = 5

    
    client_a = DiscreteLog(g, P, p, x)
    client_b = DiscreteLog(g, P, p)
    
    start_response = utime.ticks_us()

    t, s = client_a.response()
    end_response = utime.ticks_us()

    client_b.verify(s, t)
    
    end_verify = utime.ticks_us()
    
    print( f"time of verify: {end_verify - end_response:.3f}" )
    print( f"time of response: {end_response - start_response:.3f}" )