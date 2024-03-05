from ..zkps.zkp_pederesen_commitments_messages import *


def test_pederesen_commitments_interactive(x, y, p, g, h):
    
    z = 11
    P = (pow(g, x, p) * pow(h, y, p))
    Q = (pow(g, x, p) * pow(h, z, p)) 
    
    client_a = PedersenCommitmentsEqualMessagesInteractive(p, g, h, x, y, z)
    client_b = PedersenCommitmentsEqualMessagesInteractive(p, g, h)
    
    c = client_b.challenge()
    t1s1, t2s2, s3 = client_a.response(c)
    client_b.verify(P, Q, t1s1, t2s2, s3)

def test_pederesen_commitments(x, y, p, g, h):
    
    z = 11
    P = (pow(g, x, p) * pow(h, y, p))
    Q = (pow(g, x, p) * pow(h, z, p))
    
    client_a = PederesenCommitmentsEqualMessages(p, g, h, x, y, z)
    client_b = PederesenCommitmentsEqualMessages(p, g, h)
 
    t1s1, t2s2, s3 = client_a.response(P, Q)   
    client_b.verify(P, Q, t1s1, t2s2, s3)

def test_pederesen_commitments_ecc(x, y, g1c, h1c, g2c, h2c):

    z = 11
    
    client_a = PederesenCommitmentsEqualMessagesEcc(x, y, z)

    P = PederesenCommitmentsEqualMessagesEcc.curve.point_add(PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(x, g1c), PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(y, h1c))
    Q = PederesenCommitmentsEqualMessagesEcc.curve.point_add(PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(x, g2c), PederesenCommitmentsEqualMessagesEcc.curve.scalar_mult(z, h2c))
    
    (t1, s1), (t2, s2), s3 = client_a.response(g1c, h1c, g2c, h2c, P, Q)
    client_b = PederesenCommitmentsEqualMessagesEcc()
    client_b.verify(g1c, h1c, g2c, h2c, P, Q, (t1, s1), (t2, s2), s3)