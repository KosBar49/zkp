import random
from abc import ABC, ABCMeta, abstractmethod
import hashlib
from re import L

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

class ZeroKnowledgeProtocolNonInteractive(ABC):
    @abstractmethod
    def response(self, statement):
        pass

    @abstractmethod
    def verify(self, statement, proof):
        pass

class DiscreteLogConjunction(ZeroKnowledgeProtocol):

    def __init__(self, g, h, P, Q, p, a=None, b=None):
        """
        Initialize the protocol parameters.
        :param g, h: Generators of the group.
        :param P, Q: Public values such that P = g^a and Q = h^b.
        :param a, b: Secret values.
        :param p: Prime modulus (optional for large groups).
        """
        self._g = g
        self._h = h
        self._P = P
        self._Q = Q
        self._a = a
        self._b = b
        self._p = p

    def commitment(self):
        """
        Generates commitments by the prover.
        :return: Tuple of commitments (g^r1, h^r2).
        """
        self._r1 = random.randint(0, self._p - 1) if self._p else random.randint(0, 2**128)
        self._r2 = random.randint(0, self._p - 1) if self._p else random.randint(0, 2**128)
        commitment1 = pow(self._g, self._r1, self._p) if self._p else pow(self._g, self._r1)
        commitment2 = pow(self._h, self._r2, self._p) if self._p else pow(self._h, self._r2)
        return commitment1, commitment2
    
    def challenge(self):
        """
        Generates a challenge by the verifier.
        :return: Challenge (random integer).
        """
        self._challenge = random.randint(1, self._p - 1) if self._p else random.randint(1, 2**128)
        return self._challenge
    
    def response(self):
        """
        Generates responses by the prover using the challenge.
        :param challenge: Challenge value from the verifier.
        :return: Tuple of responses (s1, s2).
        """
        s1 = (self._r1 + self._challenge * self._a) % (self._p - 1) #if self._p else 2**129)
        s2 = (self._r2 + self._challenge * self._b) % (self._p - 1) #if self._p else 2**129)
        return s1, s2

    def verify(self, commitment1, commitment2, response1, response2, challange):
        """
        Verifies the responses from the prover.
        """
        lhs1 = pow(self._g, response1, self._p) if self._p else pow(self._g, response1)
        lhs2 = pow(self._h, response2, self._p) if self._p else pow(self._h, response2)
        rhs1 = (commitment1 * pow(self._P, challange, self._p)) % self._p #if self._p else commitment1 * pow(self._P, self._challenge)
        rhs2 = (commitment2 * pow(self._Q, challange, self._p)) % self._p #if self._p else commitment2 * pow(self._Q, self._challenge)
        assert lhs1 == rhs1 and lhs2 == rhs2

class DiscreteLogConjunctionEcc(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None, y = None):
        
        if x and y:
            self._x = x
            self._y = y
            
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
        r1 = DiscreteLogConjunctionEcc.curve.get_random()
        r2 = DiscreteLogConjunctionEcc.curve.get_random()
        t1 = DiscreteLogConjunctionEcc.curve.scalar_mult(r1, g)
        t2 = DiscreteLogConjunctionEcc.curve.scalar_mult(r2, h)
        c = DiscreteLogConjunctionEcc.curve.hash_points( [ g, h, P, Q, t1, t2 ] )
        s1 = ((r1 + c * self._x) % DiscreteLogConjunctionEcc.curve.order )
        s2 = ((r2 + c * self._y) % DiscreteLogConjunctionEcc.curve.order )
        return (t1, s1), (t2, s2)
    
    def verify(self, g, h, P, Q, t1s1, t2s2):
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
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        c = DiscreteLogConjunctionEcc.curve.hash_points( [ g, h, P, Q, t1, t2 ] )
        lhs1 = DiscreteLogConjunctionEcc.curve.scalar_mult(s1, g)
        rhs1 = DiscreteLogConjunctionEcc.curve.point_add(t1, DiscreteLogConjunctionEcc.curve.scalar_mult(c, P))
        lhs2 = DiscreteLogConjunctionEcc.curve.scalar_mult(s2, h)
        rhs2 = DiscreteLogConjunctionEcc.curve.point_add(t2, DiscreteLogConjunctionEcc.curve.scalar_mult(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)

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

class DiscreteLogNonInteractiveEcc(ZeroKnowledgeProtocolNonInteractive):

    curve = get_curve('secp256r1')
    
    def __init__(self, x = None):
        """
        Initializes the object with an optional value for x.
        Parameters:
            x (optional): An optional value for x.
        Returns:
            None
        """
        if x:
            self._x = x
            DiscreteLogNonInteractiveEcc.y = DiscreteLogNonInteractiveEcc.curve.scalar_mult(x, DiscreteLogNonInteractiveEcc.curve.g)

    def response(self):
        """
        Generate a response using the DiscreteLogNonInteractiveEcc algorithm.
        
        Returns:
            tuple: A tuple containing the calculated values t and s.
                - t (Point): The calculated point t.
                - s (int): The calculated value s.
        """
        r  = DiscreteLogNonInteractiveEcc.curve.get_random()
        t =  DiscreteLogNonInteractiveEcc.curve.scalar_mult(r, DiscreteLogNonInteractiveEcc.curve.g)
        c = DiscreteLogNonInteractiveEcc.curve.hash_points( [ DiscreteLogNonInteractiveEcc.curve.g, DiscreteLogNonInteractiveEcc.y, t ] )
        s = ((r + c * self._x) % DiscreteLogNonInteractiveEcc.curve.order )
        return t, s

    def verify(self, t, s):
        """
        Verify the equality of two values by performing a discrete logarithm non-interactive elliptic curve cryptography (ECC) verification.
        
        Args:
            t: The first value to be verified.
            s: The second value to be verified.
        
        Returns:
            None
            
        Raises:
            AssertionError: If the verification fails (i.e., the values are not equal).
        """
        c = DiscreteLogNonInteractiveEcc.curve.hash_points( [ DiscreteLogNonInteractiveEcc.curve.g, DiscreteLogNonInteractiveEcc.y, t ] )
        lhs = DiscreteLogNonInteractiveEcc.curve.scalar_mult(s, DiscreteLogNonInteractiveEcc.curve.g)
        yc = DiscreteLogNonInteractiveEcc.curve.scalar_mult(c, DiscreteLogNonInteractiveEcc.y)
        rhs = DiscreteLogNonInteractiveEcc.curve.point_add(t, yc)
        assert lhs == rhs

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
        s = ((r + c * self._x) % DiscreteLogNonInteractiveEcc.curve.order )
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

class DiscreteLogDisjunction(ZeroKnowledgeProtocolNonInteractive):

    def __init__(self, g, h, P, Q, p, x=None):
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

    def response(self):
        r1 = random.randint(0, self._p - 1)
        c2 = random.randint(0, self._p - 1)
        s2 = random.randint(0, self._p - 1)

        t1 = pow(self._g, r1, self._p)
        t2 = (pow(self._h, s2, self._p) * pow(self._Q, (0 - c2), self._p)) % self._p

        cha1 = str(self._g) + str(self._h) + str(self._P) + str(self._Q) + str(t1) + str(t2)
        hash_ = hashlib.md5()
        hash_.update(cha1.encode())
        c = int(hash_.hexdigest(), 16) % self._p

        c1 = (c - c2) % self._p 

        s1 = ( r1 + c1 * self._x ) % (self._p - 1)

        return (t1, c1, s1), (t2, c2, s2)

    def verify(self, g, h, P, Q, t1c1s1, t2c2s2):
        (t1, c1, s1) = t1c1s1
        (t2, c2, s2) = t2c2s2

        cha1 = str(g) + str(h) + str(P) + str(Q) + str(t1) + str(t2)
        hash_ = hashlib.md5()
        hash_.update(cha1.encode())
        c = int(hash_.hexdigest(), 16) % self._p

        assert (c == (c1 + c2) % self._p )

        lhs1 = pow(g, s1, self._p)
        rhs1 = (t1 * pow(P, c1, self._p)) % self._p

        lhs2 = pow(h, s2, self._p)
        rhs2 = (t2 * pow(Q, c2, self._p)) % self._p
        print(rhs1)
        print(lhs1)
        print(rhs2)
        print(lhs2)

        assert lhs1 == rhs1 and lhs2 == rhs2
        
class DiscreteLogDisjunctionEcc(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None):
        if x:
            self._x = x
            
    def response(self, g, h, P, Q):
        
        r1 = DiscreteLogDisjunctionEcc.curve.get_random()
        c2 = DiscreteLogDisjunctionEcc.curve.get_random()
        s2 = DiscreteLogDisjunctionEcc.curve.get_random()
        
        t1 = DiscreteLogDisjunctionEcc.curve.scalar_mult(r1, g)
        t2 = DiscreteLogDisjunctionEcc.curve.point_add(DiscreteLogDisjunctionEcc.curve.scalar_mult(s2, h), DiscreteLogDisjunctionEcc.curve.scalar_mult( (0-c2) % DiscreteLogDisjunctionEcc.curve.order , Q))
        c = DiscreteLogDisjunctionEcc.curve.hash_points( [ g, h, P, Q, t1, t2 ] )
        c1 = (c - c2) % DiscreteLogDisjunctionEcc.curve.order
        s1 = ((r1 + c1 * self._x) % DiscreteLogDisjunctionEcc.curve.order  ) % DiscreteLogDisjunctionEcc.curve.order 
        return (t1, c1, s1), (t2, c2, s2)
    
    def verify(self, g, h, P, Q, t1cs1, t2cs2):
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
        (t1, c1, s1) = t1cs1
        (t2, c2, s2) = t2cs2
        c = DiscreteLogDisjunctionEcc.curve.hash_points( [ g, h, P, Q, t1, t2 ] )
        assert (c == (c1 + c2) % DiscreteLogDisjunctionEcc.curve.order )
        lhs1 = DiscreteLogDisjunctionEcc.curve.scalar_mult(s1, g)
        rhs1 = DiscreteLogDisjunctionEcc.curve.point_add(t1, DiscreteLogDisjunctionEcc.curve.scalar_mult(c1, P))
        lhs2 = DiscreteLogDisjunctionEcc.curve.scalar_mult(s2, h)
        rhs2 = DiscreteLogDisjunctionEcc.curve.point_add(t2, DiscreteLogDisjunctionEcc.curve.scalar_mult(c2, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
        
class PedersenCommitment(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None, y = None) -> None:
        if x and y:
            self._x = x
            self._y = y
            
    def response(self, g, h, P):
        r1 = PedersenCommitment.curve.get_random()
        r2 = PedersenCommitment.curve.get_random()
        
        t = PedersenCommitment.curve.point_add(PedersenCommitment.curve.scalar_mult(r1, g), PedersenCommitment.curve.scalar_mult(r2, h))
        c = PedersenCommitment.curve.hash_points( [ g, h, P, t ] )
        s1 = ((r1 + c * self._x) % PedersenCommitment.curve.order )
        s2 = ((r2 + c * self._y) % PedersenCommitment.curve.order )
        return t, s1, s2
    
    def verify(self, g, h, P, t, s1, s2):
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
        lhs = PedersenCommitment.curve.point_add(PedersenCommitment.curve.scalar_mult(s1, g), PedersenCommitment.curve.scalar_mult(s2, h))
        c = PedersenCommitment.curve.hash_points([g, h, P, t])
        rhs = PedersenCommitment.curve.point_add(t , PedersenCommitment.curve.scalar_mult(c, P))
        assert (lhs == rhs)
        
class PederesenCommitmentEqual(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None, y = None) -> None:
        if x and y:
            self._x = x
            self._y = y
            
    def response(self, g1, h1, g2, h2, P, Q):
        r1 = PederesenCommitmentEqual.curve.get_random()
        r2 = PederesenCommitmentEqual.curve.get_random()
        t1 = PederesenCommitmentEqual.curve.point_add(PederesenCommitmentEqual.curve.scalar_mult(r1, g1), PederesenCommitmentEqual.curve.scalar_mult(r2, h1))
        t2 = PederesenCommitmentEqual.curve.point_add(PederesenCommitmentEqual.curve.scalar_mult(r1, g2), PederesenCommitmentEqual.curve.scalar_mult(r2, h2))
        c = PederesenCommitmentEqual.curve.hash_points( [ g1, h1, g2, h2, P, Q, t1, t2 ] )
        s1 = ((r1 + c * self._x) % PederesenCommitmentEqual.curve.order )
        s2 = ((r2 + c * self._y) % PederesenCommitmentEqual.curve.order )
        return (t1, s1), (t2, s2)
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        lhs1 = PederesenCommitmentEqual.curve.point_add(PederesenCommitmentEqual.curve.scalar_mult(s1, g1), PederesenCommitmentEqual.curve.scalar_mult(s2, h1))
        lhs2 = PederesenCommitmentEqual.curve.point_add(PederesenCommitmentEqual.curve.scalar_mult(s1, g2), PederesenCommitmentEqual.curve.scalar_mult(s2, h2))
        c = PederesenCommitmentEqual.curve.hash_points([g1, h1, g2, h2, P, Q, t1, t2])
        rhs1 = PederesenCommitmentEqual.curve.point_add(t1 , PederesenCommitmentEqual.curve.scalar_mult(c, P))
        rhs2 = PederesenCommitmentEqual.curve.point_add(t2 , PederesenCommitmentEqual.curve.scalar_mult(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
        
class PederesenCommitmentsEqual(ZeroKnowledgeProtocolNonInteractive):
    
    curve = get_curve('secp256r1')
    def __init__(self, x = None, y = None, z = None) -> None:
        if x and y and z:
            self._x = x
            self._y = y
            self._z = z
    
    def response(self, g1, h1, g2, h2, P, Q):
        r1 = PederesenCommitmentsEqual.curve.get_random()
        r2 = PederesenCommitmentsEqual.curve.get_random()
        r3 = PederesenCommitmentsEqual.curve.get_random()
        
        t1 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(r1, g1), PederesenCommitmentsEqual.curve.scalar_mult(r2, h1))
        t2 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(r1, g2), PederesenCommitmentsEqual.curve.scalar_mult(r3, h2))
        
        c = PederesenCommitmentsEqual.curve.hash_points( [ g1, h1, g2, h2, P, Q, t1, t2 ] )
        
        s1 = ((r1 + c * self._x) % PederesenCommitmentsEqual.curve.order )
        s2 = ((r2 + c * self._y) % PederesenCommitmentsEqual.curve.order )
        s3 = ((r3 + c * self._z) % PederesenCommitmentsEqual.curve.order )
        return (t1, s1), (t2, s2), s3
    
    def verify(self, g1, h1, g2, h2, P, Q, t1s1, t2s2, s3):
        (t1, s1) = t1s1
        (t2, s2) = t2s2
        lhs1 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(s1, g1), PederesenCommitmentsEqual.curve.scalar_mult(s2, h1))
        lhs2 = PederesenCommitmentsEqual.curve.point_add(PederesenCommitmentsEqual.curve.scalar_mult(s1, g2), PederesenCommitmentsEqual.curve.scalar_mult(s3, h2))
        c = PederesenCommitmentsEqual.curve.hash_points([g1, h1, g2, h2, P, Q, t1, t2])
        rhs1 = PederesenCommitmentsEqual.curve.point_add(t1 , PederesenCommitmentsEqual.curve.scalar_mult(c, P))
        rhs2 = PederesenCommitmentsEqual.curve.point_add(t2 , PederesenCommitmentsEqual.curve.scalar_mult(c, Q))
        assert (lhs1 == rhs1) and (lhs2 == rhs2)
        
class DiscreteLogInequality(ZeroKnowledgeProtocolNonInteractive): # not working
    
    curve = get_curve('secp256r1')
    
    def __init__(self, x = None, y = None):
        self._x = x
        self._y = y
        
    def response(self, g, h, P, Q):
        r = DiscreteLogInequality.curve.get_random()
        
        alpha = (self._x * r) % DiscreteLogInequality.curve.order
        beta = (0 - r) % DiscreteLogInequality.curve.order
        
        ar = DiscreteLogInequality.curve.scalar_mult( alpha, h )
        qr = DiscreteLogInequality.curve.scalar_mult( beta, Q )
        
        C = DiscreteLogInequality.curve.point_add(ar, qr)
        print(f"C: {C}")

        iden = DiscreteLogInequality.curve.point_add(C, C)
        print(f"iden: {iden}")
        client = PederesenCommitmentEqual(alpha, beta)
        (t1, s1), (t2, s2) = client.response(g, P, h, Q, iden, C)
        return C, (t1, s1), (t2, s2)
    
    def verify(self, g, h, P, Q, C, t1s1, t2s2 ):
       
       iden = DiscreteLogInequality.curve.point_add(C, C)
       proover = PederesenCommitmentEqual()
       proover.verify(g, P, h, Q, iden, C, t1s1, t2s2)
