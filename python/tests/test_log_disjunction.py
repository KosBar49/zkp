import pytest
from zkps.zkp_log_disjunction import *

@pytest.mark.interactive
def test_discrete_log_disjuntion_interactive(x, g, h, p, P, Q):

    client_a = DiscreteLogDisjunctionInteractive(g, h, P, Q, p, x)
    client_b = DiscreteLogDisjunctionInteractive(g, h, P, Q, p)
    
    (t1, t2) = client_a.commitment()
    c = client_b.challenge()
    c1s1, c2s2 = client_a.response(c)
    client_b.verify(g, h, P, Q, c1s1, c2s2, t1, t2)   

@pytest.mark.noninteractive
@pytest.mark.parametrize("hash_function", ["sha1", "md5", "sha256", "sha512"])
def test_discrete_log_disjunction(x, g, h, p, P, Q, hash_function):

    client_a = DiscreteLogDisjunction(g, h, P, Q, p, x)
    client_b = DiscreteLogDisjunction(g, h, P, Q, p)

    DiscreteLogDisjunction.supported_hash_name = hash_function
    
    t1c1s1, t2c2s2 = client_a.response()
    client_b.verify(g, h, P, Q, t1c1s1, t2c2s2)
    
@pytest.mark.ecc 
def test_discrete_log_disjunction_ecc(x, h1c, g1c, PC, QC):
    
    client_a = DiscreteLogDisjunctionEcc(x)
    client_b = DiscreteLogDisjunctionEcc()
    
    t1c1s1, t2c2s2 = client_a.response(g1c, h1c, PC, QC)
    client_b.verify(g1c, h1c, PC, QC, t1c1s1, t2c2s2)