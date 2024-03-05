from ..zkps.zkp_log_equality import *

def test_discrete_log_equality_interactive(x, g, h, p, P, xQ):

    client_a = DiscreteLogEqualityInteractive(g, P, h, xQ, p, x)
    client_b = DiscreteLogEqualityInteractive(g, P, h, xQ, p)
    
    t1, t2 = client_a.commitments()
    c = client_b.challenge()
    s = client_a.response(c)
    client_b.verify(c, s, t1, t2)
    
def test_discrete_log_equality(x, g, h, p, P, xQ):

    client_a = DiscreteLogEquality(g, P, h, xQ, p, x)
    client_b = DiscreteLogEquality(g, P, h, xQ, p)
    
    c, s = client_a.response()
    client_b.verify(c, s)

def test_discrete_log_equality_ecc(x, g1c, h1c, PC):
    
    Q = DiscreteLogEqualityEcc.curve.scalar_mult(x, h1c)
    
    client_a = DiscreteLogEqualityEcc(x)
    client_b = DiscreteLogEqualityEcc()
    
    (t1, t2, s) = client_a.response(g1c, h1c, PC, Q)
    client_b.verify(g1c, h1c, PC, Q, t1, t2, s)