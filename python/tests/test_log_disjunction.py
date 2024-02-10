from ..zkps.zkp_log_disjunction import *

def test_discrete_log_disjuntion_interactive():

    g = 2
    h = 3
    p = 17
    a = 4  # Secret value known to prover
    P = pow(g, a, p)
    Q = pow(h, a, p)  # Using the same 'a' for simplicity

    client_a = DiscreteLogDisjunctionInteractive(g, h, P, Q, p, a)
    client_b = DiscreteLogDisjunctionInteractive(g, h, P, Q, p) 
    c = client_b.challenge()
    t1c1s1, t2c2s2 = client_a.response(c)
    client_b.verify(g, h, P, Q, t1c1s1, t2c2s2)   

def test_discrete_log_disjunction():
    g = 2
    h = 3
    p = 17
    a = 4  # Secret value known to prover
    P = pow(g, a, p)
    Q = pow(h, a, p)  # Using the same 'a' for simplicity

    client_a = DiscreteLogDisjunction(g, h, P, Q, p, a)
    t1c1s1, t2c2s2 = client_a.response()
    client_b = DiscreteLogDisjunction(g, h, P, Q, p)
    client_b.verify(g, h, P, Q, t1c1s1, t2c2s2)
    
def test_discrete_log_disjunction_ecc():
    secret = 5
    b = 7
    client_a = DiscreteLogDisjunctionEcc(secret)
    
    g, h = DiscreteLogDisjunctionEcc.curve.get_generators(2)

    P = DiscreteLogDisjunctionEcc.curve.scalar_mult(secret, g)
    Q = DiscreteLogDisjunctionEcc.curve.scalar_mult(b, h)

    t1c1s1, t2c2s2 = client_a.response(g, h, P, Q)
    client_b = DiscreteLogDisjunctionEcc()
    client_b.verify(g, h, P, Q, t1c1s1, t2c2s2)