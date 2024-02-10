from ..zkps.zkp_log_discrete import *

def test_discrete_log_interactive():
    
    y = 2**5

    client_a = DiscreteLogInteractive(2, y, 13, 5)
    c = client_a.commitment()

    client_b = DiscreteLogInteractive(2, y, 13)
    C = client_b.challenge()
    res = client_a.response(C)
    
    client_b.verify(res, c)

def test_discrete_log():
    g = 2 # x = 5
    y = 2**5
    client_a = DiscreteLog(2, y, 13, 5)
    r, V = client_a.response()
    client_b = DiscreteLog(2, y, 13)
    client_b.verify(r, V)
    
def test_discrete_log_ecc():
    client_a = DiscreteLogEcc(5)
    (t, s) = client_a.response()
    client_b = DiscreteLogEcc()
    client_b.verify(t, s)