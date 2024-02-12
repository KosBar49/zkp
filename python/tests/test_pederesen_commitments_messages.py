from ..zkps.zkp_pederesen_commitments_messages import *


def test_pederesen_commitments_interactive():
    p = 1019
    g = 2 
    h = 3     

    x = 5
    y = 7
    z = 11
    P = (pow(g, x, p) * pow(h, y, p))
    Q = (pow(g, x, p) * pow(h, z, p)) 
    
    client_a = PedersenCommitmentsEqualMessagesInteractive(p, g, h, x, y, z)
    client_b = PedersenCommitmentsEqualMessagesInteractive(p, g, h)
    c = client_b.challenge()
    t1s1, t2s2, s3 = client_a.response(c)
    client_b.verify(P, Q, t1s1, t2s2, s3)

def test_pederesen_commitments():
    p = 1019
    g = 2 
    h = 3     

    x = 5
    y = 7
    z = 11

    client_a = PederesenCommitmentsEqualMessages(p, g, h, x, y, z)
    P = (pow(g, x, p) * pow(h, y, p))
    Q = (pow(g, x, p) * pow(h, z, p)) 

    t1s1, t2s2, s3 = client_a.response(P, Q)
    client_b = PederesenCommitmentsEqualMessages(p, g, h)
    client_b.verify(P, Q, t1s1, t2s2, s3)

def test_pederesen_commitments_ecc():
    secret = 5
    y = 7
    z = 11
    
    client_a = PederesenCommitmentsEqualMessagesEcc(secret, y, z)
    g1, h1, g2, h2 = PederesenCommitmentsEqualMessagesEcc.curve.get_generators(4)
    P = PederesenCommitmentsEqualMessagesEcc.curve.point_add(PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(secret, g1), PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(y, h1))
    Q = PederesenCommitmentsEqualMessagesEcc.curve.point_add(PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(secret, g2), PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(z, h2))
    
    (t1, s1), (t2, s2), s3 = client_a.response(g1, h1, g2, h2, P, Q)
    client_b = PederesenCommitmentsEqualMessagesEcc()
    client_b.verify(g1, h1, g2, h2, P, Q, (t1, s1), (t2, s2), s3)