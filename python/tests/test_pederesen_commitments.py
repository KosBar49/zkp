from ..zkps.zkp_pederesen_commitments import *

# do not occur in any other tests so globally defined here
X = 5
Y = 7
MODULO = 1019
G1 = 2
H1 = 3
G2 = 5 
H2 = 7
P = (pow(G1, X, MODULO) * pow(H1, Y, MODULO)) % MODULO
Q = (pow(G2, X, MODULO) * pow(H2, Y, MODULO)) % MODULO

def test_pederesen_commitment_eq_message_randomness_interactive(x, y, p, g, h, g2, h2, p_test_pederesnen_commitment_eq_message_randomness, \
    q_test_pederesnen_commitment_eq_message_randomness):
 
    client_a = PedersenCommitmentsEqualInteractive(p, x, y)
    client_b = PedersenCommitmentsEqualInteractive(p)
    
    c = client_b.challenge()
    t1s1, t2s2 = client_a.response(g, h, g2, h2, c)
    client_b.verify(g, h, g2, h2, p_test_pederesnen_commitment_eq_message_randomness, \
        q_test_pederesnen_commitment_eq_message_randomness, t1s1, t2s2)

def test_pedersen_commitment_eq_message_randomness():
    
    client_a = PedersenCommitmentsEqual(X, Y, MODULO)
    client_b = PedersenCommitmentsEqual(p=MODULO)
    
    (t1, s1), (t2, s2) = client_a.response(G1, H1, G2, H2, P, Q)
    client_b.verify(G1, H1, G2, H2, P, Q, (t1, s1), (t2, s2))

def test_pederesen_commitment_eq_message_randomness_ecc(x, y, g1c, h1c, g2c, h2c):

    P = PederesenCommitmentsEqualEcc.curve.point_add(PederesenCommitmentsEqualEcc.curve.scalar_mult(x, g1c), PederesenCommitmentsEqualEcc.curve.scalar_mult(y, h1c))
    Q = PederesenCommitmentsEqualEcc.curve.point_add(PederesenCommitmentsEqualEcc.curve.scalar_mult(x, g2c), PederesenCommitmentsEqualEcc.curve.scalar_mult(y, h2c))
    
    client_a = PederesenCommitmentsEqualEcc(x, y)
    client_b = PederesenCommitmentsEqualEcc()
    (t1, s1), (t2, s2) = client_a.response(g1c, h1c, g2c, h2c, P, Q)
    client_b.verify(g1c, h1c, g2c, h2c, P, Q, (t1, s1), (t2, s2))