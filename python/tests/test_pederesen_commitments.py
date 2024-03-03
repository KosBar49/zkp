from ..zkps.zkp_pederesen_commitments import *

def test_pederesen_commitments_interactive(x, y, p):

    g1, h1, g2, h2 = 2, 3, 5, 7     
    P = (pow(g1, x, p) * pow(h1, y, p)) % p
    Q = (pow(g2, x, p) * pow(h2, y, p)) % p
    
    client_a = PedersenCommitmentsEqualInteractive(p, x, y)
    client_b = PedersenCommitmentsEqualInteractive(p)
    
    c = client_b.challenge()
    t1s1, t2s2 = client_a.response(g1, h1, g2, h2, c)
    client_b.verify(g1, h1, g2, h2, P, Q, t1s1, t2s2)

def test_pedersen_commitment_eq_message_randomness_no_ecc(x, y, p):

    g1, h1, g2, h2 = 2, 3, 5, 7
    P = (pow(g1, x, p) * pow(h1, y, p)) % p
    Q = (pow(g2, x, p) * pow(h2, y, p)) % p
    
    client_a = PedersenCommitmentsEqual(x, y, p)
    client_b = PedersenCommitmentsEqual(p=p)
    
    (t1, s1), (t2, s2) = client_a.response(g1, h1, g2, h2, P, Q)
    client_b.verify(g1, h1, g2, h2, P, Q, (t1, s1), (t2, s2))

def test_pederesen_commitment_eq_message_randomness_ecc(x, y):

    g1, h1, g2, h2 = PederesenCommitmentsEqualEcc.curve.get_generators(4)
    P = PederesenCommitmentsEqualEcc.curve.point_add(PederesenCommitmentsEqualEcc.curve.scalar_mult(x, g1), PederesenCommitmentsEqualEcc.curve.scalar_mult(y, h1))
    Q = PederesenCommitmentsEqualEcc.curve.point_add(PederesenCommitmentsEqualEcc.curve.scalar_mult(x, g2), PederesenCommitmentsEqualEcc.curve.scalar_mult(y, h2))
    
    client_a = PederesenCommitmentsEqualEcc(x, y)
    client_b = PederesenCommitmentsEqualEcc()
    (t1, s1), (t2, s2) = client_a.response(g1, h1, g2, h2, P, Q)
    client_b.verify(g1, h1, g2, h2, P, Q, (t1, s1), (t2, s2))