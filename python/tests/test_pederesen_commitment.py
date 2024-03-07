from ..zkps.zkp_pederesen_commitment import *

def test_pedersen_commitment_interactive(x, y, g, h, p):
    
    client_a = PedersenCommitmentInteractive(p, g, h, x, y)
    client_b = PedersenCommitmentInteractive(p, g, h)

    t = client_a.commit()
    c = client_b.challenge()
    s1, s2 = client_a.response(c)
    client_b.verify(t, c, s1, s2)   
    
def test_pedersen_commitment(x, y, g, h, p, p_pederesen_commitment):
     
    client_a = PedersenCommitment(p, g, h, x, y)
    client_b = PedersenCommitment(p, g, h)
    
    (t, s1, s2) = client_a.response(p_pederesen_commitment)
    client_b.verify(g, h, p_pederesen_commitment, t, s1, s2)

def test_pederesen_commitment_ecc(x, y, g1c, h1c, p_ecc_pederesen_commitment):

    client_a = PedersenCommitmentEcc(x, y)
    client_b = PedersenCommitmentEcc()
    
    (t, s1, s2) = client_a.response(g1c, h1c, p_ecc_pederesen_commitment)
    client_b.verify(g1c, h1c, p_ecc_pederesen_commitment, t, s1, s2)