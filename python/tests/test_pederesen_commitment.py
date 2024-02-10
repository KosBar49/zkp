from ..zkps.zkp_pederesen_commitment import *

def test_pedersen_commitment_interactive():
    p = 23
    g = 5
    h = 2
    x = 5
    y = 7
    
    client_a = PedersenCommitmentInteractive(p, g, h, x, y)
    
    t = client_a.commit()
    client_b = PedersenCommitmentInteractive(p, g, h)
    c = client_b.challenge()
    s1, s2 = client_a.response(c)
    client_b.verify(t, c, s1, s2)   
    
def test_pedersen_commitment():
    # Prime order p and generators g, h for the cyclic group
    p = 1019  # Example prime number; in practice, use a large prime
    g = 2     # Example generator; in practice, ensure g is a generator of the group
    h = 3     # Another generator, unrelated to g

    # Secrets x and y
    secret_x = 5
    secret_y = 7

    # Public value P (for simplicity, it's not directly derived from x, y in this example)
    P = (pow(g, secret_x, p) * pow(h, secret_y, p)) % p

    # Initialize PedersenCommitmentNonInteractive with secrets
    client_a = PedersenCommitment(p, g, h, secret_x, secret_y)
    
    # Client A generates a response (commitment and proofs) for the public value P
    (t, s1, s2) = client_a.response(P)
    
    # Initialize another PedersenCommitmentNonInteractive instance for verification
    # No need for secrets since we're only verifying
    client_b = PedersenCommitment(p, g, h)
    
    # Client B verifies the commitment and proofs
    client_b.verify(g, h, P, t, s1, s2)

def test_pederesen_commitment_ecc():
    secret = 5
    secret_2 = 7
    client_a = PedersenCommitmentEcc(secret, secret_2)
    g, h = PedersenCommitmentEcc.curve.get_generators(2)
    P = PedersenCommitmentEcc.curve.point_add(PedersenCommitmentEcc.curve.scalar_mult(secret, g), PedersenCommitmentEcc.curve.scalar_mult(secret_2, h))
    (t, s1, s2) = client_a.response(g, h, P)
    client_b = PedersenCommitmentEcc()
    client_b.verify(g, h, P, t, s1, s2)