from ..zkps.zkp_log_discrete import *

def test_discrete_log_interactive():
    g = 2
    x = 5
    p = 13
    P = pow(g, x, p)

    client_a = DiscreteLogInteractive(g, P, p, x)
    client_b = DiscreteLogInteractive(g, P, p)
    
    t = client_a.commitment()
    c = client_b.challenge()
    s = client_a.response(c)
    client_b.verify(s, t)

def test_discrete_log():
    g = 2
    x = 5
    p = 13
    P = pow(g, x, p)
    
    client_a = DiscreteLog(g, P, p, x)
    client_b = DiscreteLog(g, P, p)
    
    t, s = client_a.response()
    client_b.verify(s, t)
    
def test_discrete_log_ecc():
    client_a = DiscreteLogEcc(5)
    client_b = DiscreteLogEcc()
    
    (t, s) = client_a.response()
    client_b.verify(s, t)