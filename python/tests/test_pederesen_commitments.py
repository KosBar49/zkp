from ..zkps.zkp_pederesen_commitments import *

def test_pederesen_commitment_eq_message_randomness_interactive(x, y, p, g, h, g2, h2, p_test_pederesnen_commitment_eq_message_randomness, \
    q_test_pederesnen_commitment_eq_message_randomness):
 
    client_a = PedersenCommitmentsEqualInteractive(p, x, y)
    client_b = PedersenCommitmentsEqualInteractive(p)
    
    c = client_b.challenge()
    t1s1, t2s2 = client_a.response(g, h, g2, h2, c)
    client_b.verify(g, h, g2, h2, p_test_pederesnen_commitment_eq_message_randomness, \
        q_test_pederesnen_commitment_eq_message_randomness, t1s1, t2s2)

def test_pedersen_commitment_eq_message_randomness(x, y, p, g, h, g2, h2, p_test_pederesnen_commitment_eq_message_randomness, \
    q_test_pederesnen_commitment_eq_message_randomness):
    
    client_a = PedersenCommitmentsEqual(p, x, y)
    client_b = PedersenCommitmentsEqual(p)
    
    (t1, s1), (t2, s2) = client_a.response(g, h, g2, h2, p_test_pederesnen_commitment_eq_message_randomness, \
        q_test_pederesnen_commitment_eq_message_randomness)
    client_b.verify(g, h, g2, h2, p_test_pederesnen_commitment_eq_message_randomness, \
        q_test_pederesnen_commitment_eq_message_randomness, (t1, s1), (t2, s2))

def test_pederesen_commitment_eq_message_randomness_ecc(x, y, g1c, h1c, g2c, h2c, \
    p_test_ecc_pederesnen_commitment_eq_message_randomness, q_test_ecc_pederesnen_commitment_eq_message_randomness):
    
    client_a = PederesenCommitmentsEqualEcc(x, y)
    client_b = PederesenCommitmentsEqualEcc()
    (t1, s1), (t2, s2) = client_a.response(g1c, h1c, g2c, h2c, p_test_ecc_pederesnen_commitment_eq_message_randomness, \
        q_test_ecc_pederesnen_commitment_eq_message_randomness)
    client_b.verify(g1c, h1c, g2c, h2c, p_test_ecc_pederesnen_commitment_eq_message_randomness, \
        q_test_ecc_pederesnen_commitment_eq_message_randomness, (t1, s1), (t2, s2))