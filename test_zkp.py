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

def test_discrete_log_ecc():
    client = DiscreteLogNonInteractiveEcc(5)
    (t, s) = client.response()
    proover = DiscreteLogNonInteractiveEcc()
    proover.verify(t, s)


def test_discrete_log_equality_ecc():
    client = DiscreteLogEqualityNonInteractiveEcc(5)
    g, h = DiscreteLogEqualityNonInteractiveEcc.curve.get_generators(2)
    P = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(5, g)
    Q = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(3, h)
    (t1, t2, s) = client.response(g, h, P, Q)