from .zkp_log_discrete import *
from .zkp_log_conjunction import *
from .zkp_log_equality import *
from .zkp_log_disjunction import *
from .zkp_pederesen_commitment import *
from .zkp_pederesen_commitments import *
from .zkp_pederesen_commitments_messages import *

def test_discrete_log_interactive():
    
    y = 2**5

    client_a = DiscreteLogInteractive(2, y, 13, 5)
    c = client_a.commitment()

    client_b = DiscreteLogInteractive(2, y, 13)
    C = client_b.challenge()
    res = client_a.response(C)
    
    client_b.verify(res, c)

def test_discrete_log():
    g = 2 # x = 5
    y = 2**5
    client_a = DiscreteLog(2, y, 13, 5)
    r, V = client_a.response()
    client_b = DiscreteLog(2, y, 13)
    client_b.verify(r, V)
    
def test_discrete_log_ecc():
    client_a = DiscreteLogEcc(5)
    (t, s) = client_a.response()
    client_b = DiscreteLogEcc()
    client_b.verify(t, s)

def test_discrete_log_equality_interactive():

    y = 2**5
    h = 3**5

    client_a = DiscreteLogEqualityInteractive(2, y, 3, h, 13, 5)
    vG, vH = client_a.commitments()
    client_b = DiscreteLogEqualityInteractive(2, y, 3, h, 13)
    C = client_b.challenge()
    
    r = client_a.response(C)
    client_b = DiscreteLogEqualityInteractive(2, y, 3, h, 13)
    client_b.verify(C, r, vG, vH)
    
def test_discrete_log_equality():

    y = 2**5
    h = 3**5

    client_a = DiscreteLogEquality(2, y, 3, h, 13, 5)
    C, r = client_a.response()
    client_b = DiscreteLogEquality(2, y, 3, h, 13)
    client_b.verify(C, r)

def test_discrete_log_equality_ecc():
    secret = 5
    client_a = DiscreteLogEqualityEcc(secret)
    g, h = DiscreteLogEqualityEcc.curve.get_generators(2)
    P = DiscreteLogEqualityEcc.curve.scalar_mult(secret, g)
    Q = DiscreteLogEqualityEcc.curve.scalar_mult(secret, h)
    (t1, t2, s) = client_a.response(g, h, P, Q)
    client_b = DiscreteLogEqualityEcc()
    client_b.verify(g, h, P, Q, t1, t2, s)

def test_discrete_log_interactive_conjunction():
    # Example parameters (for demonstration purposes, in practice, use large prime numbers and generators)
    g = 2
    h = 3
    p = 17  # Large prime for a real implementation
    a = 4
    b = 5
    P = pow(g, a, p)
    Q = pow(h, b, p)

    client_a = DiscreteLogConjunctionInteractive(g, h, P, Q, p, a, b)
    commitment1, commitment2 = client_a.commitment()
    challenge = client_a.challenge()
    response1, response2 = client_a.response()
    client_b = DiscreteLogConjunctionInteractive(g, h, P, Q, p)
    client_b.verify(commitment1, commitment2, response1, response2, challenge)
    
def test_discrete_log_conjunction():
    # Example parameters (for demonstration purposes, in practice, use large prime numbers and generators)
    g = 2
    h = 3
    p = 17  # Large prime for a real implementation
    a = 4
    b = 5
    P = pow(g, a, p)
    Q = pow(h, b, p)

    # Create an instance of DiscreteLogConjunction with known secret 'a'
    prover = DiscreteLogConjunction(g, h, P, Q, p, a, b)

    # Generate the response (non-interactive, so no commitment or external challenge)
    (t1, s1), (t2, s2) = prover.response()

    # Another instance or the same instance can be used for verification
    # Here, we use the same instance for simplicity
    prover.verify(g, h, P, Q, (t1, s1), (t2, s2))

    
def test_discrete_log_conjunction_ecc():
    secret = 5
    secret_2 = 7
    client_a = DiscreteLogConjunctionEcc(secret, secret_2)
    g, h = DiscreteLogConjunctionEcc.curve.get_generators(2)
    P = DiscreteLogConjunctionEcc.curve.scalar_mult(secret, g)
    Q = DiscreteLogConjunctionEcc.curve.scalar_mult(secret_2, h)
    (t1, s1), (t2, s2) = client_a.response(g, h, P, Q)
    client_b = DiscreteLogConjunctionEcc()
    client_b.verify(g, h, P, Q, (t1, s1), (t2, s2))

def test_discrete_log_disjuntion_interactive():

    g = 2
    h = 3
    p = 17
    a = 4  # Secret value known to prover
    P = pow(g, a, p)
    Q = pow(h, a, p)  # Using the same 'a' for simplicity

    client_a = DiscreteLogDisjunctionInteractive(g, h, P, Q, p, a)
    client_b = DiscreteLogDisjunctionInteractive(g, h, P, Q, p) 
    c = client_b.challenge()
    t1c1s1, t2c2s2 = client_a.response(c)
    client_b.verify(g, h, P, Q, t1c1s1, t2c2s2)   

def test_discrete_log_disjunction():
    g = 2
    h = 3
    p = 17
    a = 4  # Secret value known to prover
    P = pow(g, a, p)
    Q = pow(h, a, p)  # Using the same 'a' for simplicity

    client_a = DiscreteLogDisjunction(g, h, P, Q, p, a)
    t1c1s1, t2c2s2 = client_a.response()
    client_b = DiscreteLogDisjunction(g, h, P, Q, p)
    client_b.verify(g, h, P, Q, t1c1s1, t2c2s2)
    
def test_discrete_log_disjunction_ecc():
    secret = 5
    b = 7
    client_a = DiscreteLogDisjunctionEcc(secret)
    
    g, h = DiscreteLogDisjunctionEcc.curve.get_generators(2)

    P = DiscreteLogDisjunctionEcc.curve.scalar_mult(secret, g)
    Q = DiscreteLogDisjunctionEcc.curve.scalar_mult(b, h)

    t1c1s1, t2c2s2 = client_a.response(g, h, P, Q)
    client_b = DiscreteLogDisjunctionEcc()
    client_b.verify(g, h, P, Q, t1c1s1, t2c2s2)
   
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
    client_a = PedersenCommitmentNonInteractive(p, g, h, secret_x, secret_y)
    
    # Client A generates a response (commitment and proofs) for the public value P
    (t, s1, s2) = client_a.response(P)
    
    # Initialize another PedersenCommitmentNonInteractive instance for verification
    # No need for secrets since we're only verifying
    client_b = PedersenCommitmentNonInteractive(p, g, h)
    
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
    
def test_pederesen_commitments_ecc():
    secret = 5
    secret2 = 7
    secret3 = 11
    
    client_a = PederesenCommitmentsEqualMessagesEcc(secret, secret2, secret3)
    g1, h1, g2, h2 = PederesenCommitmentsEqualMessagesEcc.curve.get_generators(4)
    P = PederesenCommitmentsEqualMessagesEcc.curve.point_add(PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(secret, g1), PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(secret2, h1))
    Q = PederesenCommitmentsEqualMessagesEcc.curve.point_add(PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(secret, g2), PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(secret3, h2))
    
    (t1, s1), (t2, s2), s3 = client_a.response(g1, h1, g2, h2, P, Q)
    client_b = PederesenCommitmentsEqualMessagesEcc()
    client_b.verify(g1, h1, g2, h2, P, Q, (t1, s1), (t2, s2), s3)
