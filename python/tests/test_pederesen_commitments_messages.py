from ..zkps.zkp_pederesen_commitments_messages import *

def test_pederesen_commitments():
    p = 1019
    g = 2 
    h = 3     

    secret1 = 5
    secret2 = 7
    secret3 = 11

    client_a = PederesenCommitmentsEqual(p, g, h, secret1, secret2, secret3)
    P = (pow(g, secret1, p) * pow(h, secret2, p))
    Q = (pow(g, secret1, p) * pow(h, secret3, p)) 

    t1s1, t2s2, s3 = client_a.response(P, Q)
    client_b = PederesenCommitmentsEqual(p, g, h)
    client_b.verify(P, Q, t1s1, t2s2, s3)

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