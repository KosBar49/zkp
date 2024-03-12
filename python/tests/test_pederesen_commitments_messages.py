import pytest
from ..zkps.zkp_pederesen_commitments_messages import *

@pytest.mark.interactive
def test_pederesen_commitments_interactive(x, y, z, p, g, h, p_pederesen_commitment, \
    q_pederen_commitments):
    
    client_a = PedersenCommitmentsEqualMessagesInteractive(p, g, h, x, y, z)
    client_b = PedersenCommitmentsEqualMessagesInteractive(p, g, h)
    
    c = client_b.challenge()
    t1s1, t2s2, s3 = client_a.response(c)
    client_b.verify(p_pederesen_commitment, q_pederen_commitments, t1s1, t2s2, s3)

@pytest.mark.noninteractive
@pytest.mark.parametrize("hash_function", ["sha1", "md5", "sha256", "sha512"])
def test_pederesen_commitments(x, y, z, p, g, h, p_pederesen_commitment, \
    q_pederen_commitments, hash_function):
    
    client_a = PederesenCommitmentsEqualMessages(p, g, h, x, y, z)
    client_b = PederesenCommitmentsEqualMessages(p, g, h)
    
    PederesenCommitmentsEqualMessages.supported_hash_name = hash_function
 
    t1s1, t2s2, s3 = client_a.response(p_pederesen_commitment, q_pederen_commitments)   
    client_b.verify(p_pederesen_commitment, q_pederen_commitments, t1s1, t2s2, s3)

@pytest.mark.ecc
def test_pederesen_commitments_ecc(x, y, z, g1c, h1c, g2c, h2c, p_ecc_pederesen_commitments_messages, \
    q_ecc_pederesen_commitments_messages):

    client_a = PederesenCommitmentsEqualMessagesEcc(x, y, z)
    
    (t1, s1), (t2, s2), s3 = client_a.response(g1c, h1c, g2c, h2c, \
        p_ecc_pederesen_commitments_messages, q_ecc_pederesen_commitments_messages)
    client_b = PederesenCommitmentsEqualMessagesEcc()
    client_b.verify(g1c, h1c, g2c, h2c, \
        p_ecc_pederesen_commitments_messages, q_ecc_pederesen_commitments_messages, (t1, s1), (t2, s2), s3)