from .zkp import *

def test_discrete_log_interactive():
    
    y = 2**5

    proover = DiscreteLogInteractive(2, y, 13, 5)
    c = proover.commitment()

    verifier = DiscreteLogInteractive(2, y, 13)
    C = verifier.challenge()
    res = proover.response(C)
    
    verifier.verify(res, c)

def test_discrete_log_noninteractive():

    y = 2**5
    proover = DiscreteLogNonInteractive(2, y, 13, 5)
    c, V = proover.challenge()
    r = proover.response()
    verifier = DiscreteLogNonInteractive(2, y, 13)
    verifier.verify(r, c, V)

def test_discrete_log_equality_noninteractive():

    y = 2**5
    h = 3**5

    proover = DiscreteLogEqualityNonInteractive(2, y, 3, h, 13, 5)
    proover.commitments()
    C = proover.challenge()
    r = proover.response()
    verifier = DiscreteLogEqualityNonInteractive(2, y, 3, h, 13)
    verifier.verify(C, r)
