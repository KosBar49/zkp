import pytest
from zkps.zkp_log_conjunction import *

@pytest.mark.interactive
def test_discrete_log_interactive_conjunction(x, y, g, h, p, P, Q):

    client_a = DiscreteLogConjunctionInteractive(g, h, P, Q, p, x, y)
    client_b = DiscreteLogConjunctionInteractive(g, h, P, Q, p)
    
    t1, t2 = client_a.commitment()
    c = client_a.challenge()
    s1, s2 = client_a.response()
    client_b.verify(t1, t2, s1, s2, c)

@pytest.mark.noninteractive
@pytest.mark.parametrize("hash_function", ["sha1", "md5", "sha256", "sha512"])
def test_discrete_log_conjunction(x, y, g, h, p, P, Q, hash_function):

    client_a = DiscreteLogConjunction(g, h, P, Q, p, x, y)
    client_b = DiscreteLogConjunction(g, h, P, Q, p)
    
    DiscreteLogConjunction.supported_hash_name = hash_function
    
    (t1, s1), (t2, s2) = client_a.response()
    client_b.verify((t1, s1), (t2, s2))

@pytest.mark.ecc
def test_discrete_log_conjunction_ecc(x, y, g1c, h1c, PC, QC):
    
    client_a = DiscreteLogConjunctionEcc(x, y)
    client_b = DiscreteLogConjunctionEcc()
    
    (t1, s1), (t2, s2) = client_a.response(g1c, h1c, PC, QC)
    client_b.verify(g1c, h1c, PC, QC, (t1, s1), (t2, s2))