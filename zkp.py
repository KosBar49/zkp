import random
from abc import ABC, abstractmethod
import hashlib

from .elliptic_curve import get_curve

class ZeroKnowledgeProtocol(ABC):
    @abstractmethod
    def response(self, statement):
        pass

    @abstractmethod
    def challenge(self):
        pass

    @abstractmethod
    def verify(self, statement, proof):
        pass


class ZeroKnowledgeProtocolEcc(ABC):
    @abstractmethod
    def response(self, statement):
        pass

    @abstractmethod
    def verify(self, statement, proof):
        pass

class DiscreteLogInteractive(ZeroKnowledgeProtocol):

    def __init__(self, g, y, p, x = None):
        """
        :param g: generator
        :param y: public key
        :param p: modulo
        :param x: secret
        """
        self._g = g
        self._y = y
        self._p = p 
        self._x = x
    
    def commitment(self):
        """
        :return: commitment (g^r mod p)
        """
        self._r = random.randint(0, self._p - 1)
        commitment = pow(self._g, self._r, self._p)
        return commitment
    
    def challenge(self):
        """        
        :return: challenge (x * c + r mod p - 1)
        """
        self._challenge = random.randint(1, self._p - 1)
        return self._challenge
    
    def response(self, challenge):
        """
        :param challenge: The challenge generated by the verifier

        :return: response (x * c + r mod p - 1)
        """
        return ( self._x * challenge + self._r ) % (self._p - 1)

    def verify(self, response, commitment):
        """
        :param response: The response generated by the prover
        :param commitment: The commitment generated by the prover
        """
        assert pow( self._g, response, self._p ) == ( pow(self._y, self._challenge) * commitment ) % self._p

class DiscreteLogNonInteractive(ZeroKnowledgeProtocol):
    """
    Implementation based on https://asecuritysite.com/zero/nizkp2
    """
    def __init__(self, g, y, p, x = None):
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

    def challenge(self):
        """
        Generates a challenge for the user.
        Parameters:
            None
        Returns:
            A tuple containing the challenge value and the computed V value.
        """
        chal = str(self._g) + str(self._x) + str(self._y)
        h = hashlib.md5()
        h.update(chal.encode())
        self._v = random.randint(0, self._p - 1)
        V = pow(self._g, self._v, self._p)
        self._c = int(h.hexdigest(), 16)
        return self._c, V

    def response(self):
        """
        Calculate the response value based on the current state of the object.
        Returns:
            int: The calculated response value.
        """
        return (self._v - self._c * self._x) % (self._p - 1)

    def verify(self, r, c, V):
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
        check = (pow(self._g, r, self._p) * pow(self._y, c, self._p)) % self._p
        assert V == check

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

class DiscreteLogNonInteractiveEcc(ZeroKnowledgeProtocolEcc):

    curve = get_curve('secp256k1')
    
    def __init__(self, x = None):
        if x:
            self._x = x
            DiscreteLogNonInteractiveEcc.y = DiscreteLogNonInteractiveEcc.curve.scalar_mult(x, DiscreteLogNonInteractiveEcc.curve.g)

    def response(self):
        r  = DiscreteLogNonInteractiveEcc.curve.get_random()
        t =  DiscreteLogNonInteractiveEcc.curve.scalar_mult(r, DiscreteLogNonInteractiveEcc.curve.g)
        c = DiscreteLogNonInteractiveEcc.curve.hash_points( [ DiscreteLogNonInteractiveEcc.curve.g, DiscreteLogNonInteractiveEcc.y, t ] )
        s = ((r + c * self._x) % DiscreteLogNonInteractiveEcc.curve.order )
        return t, s

    def verify(self, t, s):
        c = DiscreteLogNonInteractiveEcc.curve.hash_points( [ DiscreteLogNonInteractiveEcc.curve.g, DiscreteLogNonInteractiveEcc.y, t ] )
        lhs = DiscreteLogNonInteractiveEcc.curve.scalar_mult(s, DiscreteLogNonInteractiveEcc.curve.g)
        yc = DiscreteLogNonInteractiveEcc.curve.scalar_mult(c, DiscreteLogNonInteractiveEcc.y)
        rhs = DiscreteLogNonInteractiveEcc.curve.point_add(t, yc)
        assert lhs == rhs


class DiscreteLogEqualityNonInteractiveEcc(ZeroKnowledgeProtocolEcc):

    curve = get_curve('P192')
    
    def __init__(self, x = None):
        if x:
            self._x = x

    def response(self, g, h, P, Q):
        r = DiscreteLogEqualityNonInteractiveEcc.curve.get_random()
        t1 = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(r, g)
        t2 = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(r, h)
        c = DiscreteLogEqualityNonInteractiveEcc.curve.hash_points( [ g, h, P, Q, t1, t2 ] )
        s = ((r + c * self._x) % DiscreteLogNonInteractiveEcc.curve.order )
        return t1, t2, s

    def verify(self, g, h, P, Q, t1, t2, s):
        c = DiscreteLogEqualityNonInteractiveEcc.curve.hash_points( [ g, h, P, Q, t1, t2 ] )
        lhs1 = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(s,g)
        rhs1 = DiscreteLogEqualityNonInteractiveEcc.curve.point_add(t1, DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(c, P))
        lhs2 = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(s,h)
        rhs2 = DiscreteLogEqualityNonInteractiveEcc.curve.point_add(t2, DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)