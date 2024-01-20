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

class ZeroKnowledgeProtocolNonInteractive(ABC):
    @abstractmethod
    def response(self, statement):
        pass

    @abstractmethod
    def verify(self, statement, proof):
        pass