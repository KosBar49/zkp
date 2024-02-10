from ..zkps.zkp_log_conjunction import *

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