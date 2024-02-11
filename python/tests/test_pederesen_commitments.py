from ..zkps.zkp_pederesen_commitments import *

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