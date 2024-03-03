from ..zkps.zkp_log_disjunction import *

def test_discrete_log_disjuntion_interactive():
    g = 2
    h = 3
    p = 17
    x = 4
    P = pow(g, x, p)
    Q = pow(h, x, p)

    client_a = DiscreteLogDisjunctionInteractive(g, h, P, Q, p, x)
    client_b = DiscreteLogDisjunctionInteractive(g, h, P, Q, p)
    
    (t1, t2) = client_a.commitment()
    c = client_b.challenge()
    c1s1, c2s2 = client_a.response(c)
    client_b.verify(g, h, P, Q, c1s1, c2s2, t1, t2)   

def test_discrete_log_disjunction():
    g = 2
    h = 3
    p = 17
    x = 4
    P = pow(g, x, p)
    Q = pow(h, x, p)

    client_a = DiscreteLogDisjunction(g, h, P, Q, p, x)
    client_b = DiscreteLogDisjunction(g, h, P, Q, p)

    t1c1s1, t2c2s2 = client_a.response()
    client_b.verify(g, h, P, Q, t1c1s1, t2c2s2)
    
def test_discrete_log_disjunction_ecc():
    x = 4
    g, h = DiscreteLogDisjunctionEcc.curve.get_generators(2)
    P = DiscreteLogDisjunctionEcc.curve.scalar_mult(x, g)
    Q = DiscreteLogDisjunctionEcc.curve.scalar_mult(x, h)

    client_a = DiscreteLogDisjunctionEcc(x)
    client_b = DiscreteLogDisjunctionEcc()
    
    t1c1s1, t2c2s2 = client_a.response(g, h, P, Q)
    client_b.verify(g, h, P, Q, t1c1s1, t2c2s2)