from ..zkps.zkp_pederesen_commitment import *

# be sure to have the same values as in the conftest.py
X = 5
Y = 7
MODULO = 1019
G = 2
H = 3
P = (pow(G, X, MODULO) * pow(H, Y, MODULO)) % MODULO

def test_pedersen_commitment_interactive(x, y, g, h, p):
    
    client_a = PedersenCommitmentInteractive(p, g, h, x, y)
    client_b = PedersenCommitmentInteractive(p, g, h)

    t = client_a.commit()
    c = client_b.challenge()
    s1, s2 = client_a.response(c)
    client_b.verify(t, c, s1, s2)   
    
def test_pedersen_commitment():
     
    client_a = PedersenCommitment(MODULO, G, H, X, Y)
    client_b = PedersenCommitment(MODULO, G, H)
    
    (t, s1, s2) = client_a.response(P)
    client_b.verify(G, H, P, t, s1, s2)

def test_pederesen_commitment_ecc(x, y, g1c, h1c, p_ecc_pederesen_commitment):

    client_a = PedersenCommitmentEcc(x, y)
    client_b = PedersenCommitmentEcc()
    
    (t, s1, s2) = client_a.response(g1c, h1c, p_ecc_pederesen_commitment)
    client_b.verify(g1c, h1c, p_ecc_pederesen_commitment, t, s1, s2)