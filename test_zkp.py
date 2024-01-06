from .zkp import *

def test_discrete_log_interactive():
    
    y = 2**5

    proover = DiscreteLogInteractive(2, y, 13, 5)
    c = proover.commitment()

    verifier = DiscreteLogInteractive(2, y, 13)
    C = verifier.challenge()
    res = proover.response(C)
    
    verifier.verify(res, c)

def test_discrete_log_noninteractive():

    y = 2**5
    proover = DiscreteLogNonInteractive(2, y, 13, 5)
    c, V = proover.challenge()
    r = proover.response()
    verifier = DiscreteLogNonInteractive(2, y, 13)
    verifier.verify(r, c, V)

def test_discrete_log_equality_noninteractive():

    y = 2**5
    h = 3**5

    proover = DiscreteLogEqualityNonInteractive(2, y, 3, h, 13, 5)
    proover.commitments()
    C = proover.challenge()
    r = proover.response()
    verifier = DiscreteLogEqualityNonInteractive(2, y, 3, h, 13)
    verifier.verify(C, r)

def test_discrete_log_ecc():
    client = DiscreteLogNonInteractiveEcc(5)
    (t, s) = client.response()
    proover = DiscreteLogNonInteractiveEcc()
    proover.verify(t, s)


def test_discrete_log_equality_ecc():
    secret = 5
    client = DiscreteLogEqualityNonInteractiveEcc(secret)
    g, h = DiscreteLogEqualityNonInteractiveEcc.curve.get_generators(2)
    P = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(secret, g)
    Q = DiscreteLogEqualityNonInteractiveEcc.curve.scalar_mult(secret, h)
    (t1, t2, s) = client.response(g, h, P, Q)
    proover = DiscreteLogEqualityNonInteractiveEcc()
    proover.verify(g, h, P, Q, t1, t2, s)
    
def test_discrete_log_conjunction():
    secret = 5
    secret_2 = 7
    client = DiscreteLogConjunction(secret, secret_2)
    g, h = DiscreteLogConjunction.curve.get_generators(2)
    P = DiscreteLogConjunction.curve.scalar_mult(secret, g)
    Q = DiscreteLogConjunction.curve.scalar_mult(secret_2, h)
    (t1, s1), (t2, s2) = client.response(g, h, P, Q)
    proover = DiscreteLogConjunction()
    proover.verify(g, h, P, Q, (t1, s1), (t2, s2))
    
def test_discrete_log_disjunction():
    secret = 5
    b = 7
    client = DiscreteLogDisjunction(secret)
    
    g, h = DiscreteLogDisjunction.curve.get_generators(2)

    P = DiscreteLogDisjunction.curve.scalar_mult(secret, g)
    Q = DiscreteLogDisjunction.curve.scalar_mult(b, h)

    t1c1s1, t2c2s2 = client.response(g, h, P, Q)
    proover = DiscreteLogDisjunction()
    proover.verify(g, h, P, Q, t1c1s1, t2c2s2)
    
def test_pederesen_commitment():
    secret = 5
    secret_2 = 7
    client = PedersenCommitment(secret, secret_2)
    g, h = PedersenCommitment.curve.get_generators(2)
    P = PedersenCommitment.curve.point_add(PedersenCommitment.curve.scalar_mult(secret, g), PedersenCommitment.curve.scalar_mult(secret_2, h))
    (t, s1, s2) = client.response(g, h, P)
    proover = PedersenCommitment()
    proover.verify(g, h, P, t, s1, s2)
    
def test_pederesen_commitment_eq_message_randomness():
    secret = 5
    secret_2 = 7
    client = PederesenCommitmentEqual(secret, secret_2)
    g1, h1, g2, h2 = PederesenCommitmentEqual.curve.get_generators(4)
    P = PederesenCommitmentEqual.curve.point_add(PederesenCommitmentEqual.curve.scalar_mult(secret, g1), PederesenCommitmentEqual.curve.scalar_mult(secret_2, h1))
    Q = PederesenCommitmentEqual.curve.point_add(PederesenCommitmentEqual.curve.scalar_mult(secret, g2), PederesenCommitmentEqual.curve.scalar_mult(secret_2, h2))
    (t1, s1), (t2, s2) = client.response(g1, h1, g2, h2, P, Q)
    proover = PederesenCommitmentEqual()
    proover.verify(g1, h1, g2, h2, P, Q, (t1, s1), (t2, s2))
    
