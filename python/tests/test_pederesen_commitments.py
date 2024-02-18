from ..zkps.zkp_pederesen_commitments import *

def test_pederesen_commitments_interactive():
    p = 1019
    g1, h1, g2, h2 = 2, 3, 5, 7     

    x = 5
    y = 7
    
    P = (pow(g1, x, p) * pow(h1, y, p)) % p
    Q = (pow(g2, x, p) * pow(h2, y, p)) % p
    
    client_a = PedersenCommitmentsEqualInteractive(p, x, y)
    client_b = PedersenCommitmentsEqualInteractive(p)
    c = client_b.challenge()
    t1s1, t2s2 = client_a.response(g1, h1, g2, h2, c)
    
    client_b.verify(g1, h1, g2, h2, P, Q, t1s1, t2s2)

def test_pedersen_commitment_eq_message_randomness_no_ecc():
    # Secrets and a large prime number
    secret = 5
    secret_2 = 7
    p = 30803  # Example large prime, in practice, should be much larger
    
    # Initialize client with secrets
    client_a = PedersenCommitmentsEqual(secret, secret_2, p)
    
    # Example base numbers (in a real application, these should be chosen carefully)
    g1, h1, g2, h2 = 2, 3, 5, 7
    
    # Compute Pedersen commitments P and Q
    P = (pow(g1, secret, p) * pow(h1, secret_2, p)) % p
    Q = (pow(g2, secret, p) * pow(h2, secret_2, p)) % p
    
    # Generate the proof
    (t1, s1), (t2, s2) = client_a.response(g1, h1, g2, h2, P, Q)
    
    # Initialize another instance for verification (no secrets needed for verification)
    client_b = PedersenCommitmentsEqual(p=p)
    
    # Verify the proof
    client_b.verify(g1, h1, g2, h2, P, Q, (t1, s1), (t2, s2))

def test_pederesen_commitment_eq_message_randomness_ecc():
    secret = 5
    secret_2 = 7
    client_a = PederesenCommitmentsEqualEcc(secret, secret_2)
    g1, h1, g2, h2 = PederesenCommitmentsEqualEcc.curve.get_generators(4)
    P = PederesenCommitmentsEqualEcc.curve.point_add(PederesenCommitmentsEqualEcc.curve.scalar_mult(secret, g1), PederesenCommitmentsEqualEcc.curve.scalar_mult(secret_2, h1))
    Q = PederesenCommitmentsEqualEcc.curve.point_add(PederesenCommitmentsEqualEcc.curve.scalar_mult(secret, g2), PederesenCommitmentsEqualEcc.curve.scalar_mult(secret_2, h2))
    (t1, s1), (t2, s2) = client_a.response(g1, h1, g2, h2, P, Q)
    client_b = PederesenCommitmentsEqualEcc()
    client_b.verify(g1, h1, g2, h2, P, Q, (t1, s1), (t2, s2))