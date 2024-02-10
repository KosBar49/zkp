from ..zkps.zkp_log_equality import *

def test_discrete_log_equality_interactive():

    y = 2**5
    h = 3**5

    client_a = DiscreteLogEqualityInteractive(2, y, 3, h, 13, 5)
    vG, vH = client_a.commitments()
    client_b = DiscreteLogEqualityInteractive(2, y, 3, h, 13)
    C = client_b.challenge()
    
    r = client_a.response(C)
    client_b = DiscreteLogEqualityInteractive(2, y, 3, h, 13)
    client_b.verify(C, r, vG, vH)
    
def test_discrete_log_equality():

    y = 2**5
    h = 3**5

    client_a = DiscreteLogEquality(2, y, 3, h, 13, 5)
    C, r = client_a.response()
    client_b = DiscreteLogEquality(2, y, 3, h, 13)
    client_b.verify(C, r)

def test_discrete_log_equality_ecc():
    secret = 5
    client_a = DiscreteLogEqualityEcc(secret)
    g, h = DiscreteLogEqualityEcc.curve.get_generators(2)
    P = DiscreteLogEqualityEcc.curve.scalar_mult(secret, g)
    Q = DiscreteLogEqualityEcc.curve.scalar_mult(secret, h)
    (t1, t2, s) = client_a.response(g, h, P, Q)
    client_b = DiscreteLogEqualityEcc()
    client_b.verify(g, h, P, Q, t1, t2, s)