import random
from abc import ABC, abstractmethod

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


class DiscreteLogInteractive(ZeroKnowledgeProtocol):

    def __init__(self, g, y, p, x = None):
        self._g = g #generator
        self._y = y
        self._p = p # modulo
        self._x = x
    
    def commitment(self):
        self._r = random.randint(0, self._p - 1)
        commitment = pow(self._g, self._r, self._p)
        return commitment
    
    def challenge(self):
        self._challenge = random.randint(1, self._p - 1)
        return self._challenge
    
    def response(self, challenge):
        return ( self._x * challenge + self._r ) % (self._p - 1)

    def verify(self, response, commitment):
        assert pow( self._g, response, self._p ) == ( pow(self._y, self._challenge) * commitment ) % self._p

class DiscreteLogNonInteractive(ZeroKnowledgeProtocol):
    pass
