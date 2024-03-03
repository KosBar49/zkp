from ..zkps.zkp_log_conjunction import *

def test_discrete_log_interactive_conjunction():
    g = 2
    h = 3
    p = 1019 
    x = 4
    y = 5
    P = pow(g, x, p)
    Q = pow(h, y, p)

    client_a = DiscreteLogConjunctionInteractive(g, h, P, Q, p, x, y)
    client_b = DiscreteLogConjunctionInteractive(g, h, P, Q, p)
    
    t1, t2 = client_a.commitment()
    challenge = client_a.challenge()
    s1, s2 = client_a.response()
    client_b.verify(t1, t2, s1, s2, challenge)
    
def test_discrete_log_conjunction():
    g = 2
    h = 3
    p = 1019
    x = 4
    y = 5
    P = pow(g, x, p)
    Q = pow(h, y, p)

    client_a = DiscreteLogConjunction(g, h, P, Q, p, x, y)
    client_b = DiscreteLogConjunction(g, h, P, Q, p)
    
    (t1, s1), (t2, s2) = client_a.response()
    client_b.verify(g, h, P, Q, (t1, s1), (t2, s2))

    
def test_discrete_log_conjunction_ecc():
    x = 5
    y = 7
    g, h = DiscreteLogConjunctionEcc.curve.get_generators(2)
    P = DiscreteLogConjunctionEcc.curve.scalar_mult(x, g)
    Q = DiscreteLogConjunctionEcc.curve.scalar_mult(y, h)
    
    client_a = DiscreteLogConjunctionEcc(x, y)
    client_b = DiscreteLogConjunctionEcc()
    
    (t1, s1), (t2, s2) = client_a.response(g, h, P, Q)
    client_b.verify(g, h, P, Q, (t1, s1), (t2, s2))