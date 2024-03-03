from ..zkps.zkp_log_discrete import *

def test_discrete_log_interactive():
    g = 2
    x = 5
    P = g**x

    client_a = DiscreteLogInteractive(2, P, 13, 5)
    client_b = DiscreteLogInteractive(2, P, 13)
    
    t = client_a.commitment()
    c = client_b.challenge()
    s = client_a.response(c)
    client_b.verify(s, t)

def test_discrete_log():
    g = 2
    x = 5
    P = g**x
    client_a = DiscreteLog(g, P, 13, x)
    client_b = DiscreteLog(g, P, 13)
    
    t, s = client_a.response()
    client_b.verify(s, t)
    
def test_discrete_log_ecc():
    client_a = DiscreteLogEcc(5)
    client_b = DiscreteLogEcc()
    
    (t, s) = client_a.response()
    client_b.verify(s, t)