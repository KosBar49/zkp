import pytest
from ..zkps.zkp_log_equality import *

@pytest.mark.interactive
def test_discrete_log_equality_interactive(x, g, h, p, P, q_discrete_log_equality):

    client_a = DiscreteLogEqualityInteractive(g, P, h, q_discrete_log_equality, p, x)
    client_b = DiscreteLogEqualityInteractive(g, P, h, q_discrete_log_equality, p)
    
    t1, t2 = client_a.commitments()
    c = client_b.challenge()
    s = client_a.response(c)
    client_b.verify(c, s, t1, t2)

@pytest.mark.noninteractive
@pytest.mark.parametrize("hash_function", ["sha1", "md5", "sha256", "sha512"])
def test_discrete_log_equality(x, g, h, p, P, q_discrete_log_equality, hash_function):

    client_a = DiscreteLogEquality(g, P, h, q_discrete_log_equality, p, x)
    client_b = DiscreteLogEquality(g, P, h, q_discrete_log_equality, p)
    
    DiscreteLogEquality.supported_hash_name = hash_function
    
    c, s = client_a.response()
    client_b.verify(c, s)

@pytest.mark.ecc
def test_discrete_log_equality_ecc(x, g1c, h1c, p_ecc_log_equality, \
    q_ecc_log_equality):
    
    client_a = DiscreteLogEqualityEcc(x)
    client_b = DiscreteLogEqualityEcc()
    
    (t1, t2, s) = client_a.response(g1c, h1c, p_ecc_log_equality, q_ecc_log_equality)
    client_b.verify(g1c, h1c, p_ecc_log_equality, q_ecc_log_equality, t1, t2, s)