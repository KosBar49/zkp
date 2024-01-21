import random
import hashlib
from .elliptic_curve import get_curve
from .interface_zkp import ZeroKnowledgeProtocol, ZeroKnowledgeProtocolNonInteractive   

class DiscreteLogEqualityNonInteractive(ZeroKnowledgeProtocol):
    """
    Implementation based on https://asecuritysite.com/zero/dleq3
    """
    def __init__(self, g, xG, h, xH, p, x = None):
        """
        :param g: generator 1
        :param xG: public key 1
        :param h: generator 2
        :param xH: public key 2
        :param p: modulo
        :param x: secret
        """
        self._p = p
        self._g = g
        self._xG = xG
        self._h = h
        self._xH = xH
        self._x = x

    def commitments(self):
        """
        Generates random values for the variables `self._v`, `self._vG`, and `self._vH`.
        Parameters:
            self (object): The instance of the class.
        
        Returns:
            None
        """
        self._v = random.randint(0, self._p - 1)
        self._vG = pow(self._g, self._v, self._p) 
        self._vH = pow(self._h, self._v, self._p)

    def challenge(self):
        """
        Computes the challenge value for the current instance.
        Parameters:
            None
        Returns:
            int: The computed challenge value.
        """
        h = hashlib.md5()
        cha1 = str(self._vG)+str(self._vH)+str(self._g) + str(self._h)
        h.update(cha1.encode()) 
        self._c = int(h.hexdigest(), 16)
        return self._c

    def response(self):
        """
        Calculates the response value based on the current object state.
        :return: The calculated response value.
        """
        self._r = (self._v - self._x * self._c) % (self._p - 1)
        return self._r

    def verify(self, c, r):
        """
        Verify DLEQ proof on a certain condition.
        Args:
            c (int): The first parameter representing a value.
            r (int): The second parameter representing a value.
        Returns:
            None
        """
        v1 = (pow(self._g, r, self._p) * pow(self._xG, c, self._p)) % self._p
        v2 = (pow(self._h, r, self._p) * pow(self._xH, c, self._p)) % self._p

        cha1 = str(v1) + str(v2) + str(self._g) + str(self._h)
        h = hashlib.md5()
        h.update(cha1.encode())
        c1 = int(h.hexdigest(), 16)
        assert c == c1

class DiscreteLogEqualityNonInteractiveEcc(ZeroKnowledgeProtocolNonInteractive):

    curve = get_curve('secp256r1')
    
    def __init__(self, x = None):
        """
        Initializes an instance of the class.
        
        Parameters:
            x (optional): The value to assign to the private attribute _x.
        
        Returns:
            None
        """
        if x:
            self._x = x

    def response(self, g, h, P, Q):
        """
        Calculates the response for the given parameters.
        Args:
            g (Point): The base point of the curve.
            h (Point): Another point on the curve.
            P (Point): A point on the curve.
            Q (Point): Another point on the curve.
        Returns:
            Tuple[Point, Point, int]: A tuple containing the calculated points t1 and t2, and the calculated integer s.
        """
        r = DiscreteLogEqualityNonInteractiveEcc.curve.get_random()
        t1 = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(r, g)
        t2 = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(r, h)
        c = DiscreteLogEqualityNonInteractiveEcc.curve.hash_points( [ g, h, P, Q, t1, t2 ] )
        s = ((r + c * self._x) % DiscreteLogEqualityNonInteractiveEcc.curve.order )
        return t1, t2, s

    def verify(self, g, h, P, Q, t1, t2, s):
        """
        Verify the equality of two discrete logarithms.
        Args:
            g (Point): The base point of the first logarithm.
            h (Point): The base point of the second logarithm.
            P (Point): The first point on the elliptic curve.
            Q (Point): The second point on the elliptic curve.
            t1 (Point): The first temporary point.
            t2 (Point): The second temporary point.
            s (Scalar): The scalar value.
        Returns:
            None
        Raises:
            AssertionError: If the equality of the discrete logarithms is not verified.
        """
        c = DiscreteLogEqualityNonInteractiveEcc.curve.hash_points( [ g, h, P, Q, t1, t2 ] )
        lhs1 = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(s, g)
        rhs1 = DiscreteLogEqualityNonInteractiveEcc.curve.point_add(t1, DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(c, P))
        lhs2 = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(s,h)
        rhs2 = DiscreteLogEqualityNonInteractiveEcc.curve.point_add(t2, DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)