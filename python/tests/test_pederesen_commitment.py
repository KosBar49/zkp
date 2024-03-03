from ..zkps.zkp_pederesen_commitment import *

def test_pedersen_commitment_interactive():
    p = 23
    g = 5
    h = 2
    x = 5
    y = 7
    
    client_a = PedersenCommitmentInteractive(p, g, h, x, y)
    client_b = PedersenCommitmentInteractive(p, g, h)

    t = client_a.commit()
    c = client_b.challenge()
    s1, s2 = client_a.response(c)
    client_b.verify(t, c, s1, s2)   
    
def test_pedersen_commitment():
    x = 5
    y = 7
    p = 1019  
    g = 2     
    h = 3         
    P = (pow(g, x, p) * pow(h, y, p)) % p
    
    client_a = PedersenCommitment(p, g, h, x, y)
    client_b = PedersenCommitment(p, g, h)
    
    (t, s1, s2) = client_a.response(P)
    client_b.verify(g, h, P, t, s1, s2)

def test_pederesen_commitment_ecc():
    x = 5
    y = 7
    client_a = PedersenCommitmentEcc(x, y)
    client_b = PedersenCommitmentEcc()

    g, h = PedersenCommitmentEcc.curve.get_generators(2)
    P = PedersenCommitmentEcc.curve.point_add(PedersenCommitmentEcc.curve.scalar_mult(x, g), PedersenCommitmentEcc.curve.scalar_mult(y, h))
    
    (t, s1, s2) = client_a.response(g, h, P)
    client_b.verify(g, h, P, t, s1, s2)