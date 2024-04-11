import pytest
from zkps.zkp_log_discrete import *

@pytest.mark.interactive
def test_discrete_log_interactive(x, g, p, P):

    client_a = DiscreteLogInteractive(g, P, p, x)
    client_b = DiscreteLogInteractive(g, P, p)
    
    t = client_a.commitment()
    c = client_b.challenge()
    s = client_a.response(c)
    client_b.verify(s, t)

@pytest.mark.noninteractive
@pytest.mark.parametrize("hash_function", ["sha1", "md5", "sha256", "sha512"])
def test_discrete_log(x, g, p, P, hash_function):
    
    client_a = DiscreteLog(g, P, p, x)
    client_b = DiscreteLog(g, P, p)
    
    DiscreteLog.supported_hash_name = hash_function
    
    t, s = client_a.response()
    client_b.verify(s, t)
    
@pytest.mark.ecc
def test_discrete_log_ecc():
    client_a = DiscreteLogEcc(5)
    client_b = DiscreteLogEcc()
    
    (t, s) = client_a.response()
    client_b.verify(s, t)