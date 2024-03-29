from zkps.elliptic_curve import get_curve

x = 5
y = 7

curve = get_curve('secp256r1')
g1, h1, g2, h2 = curve.get_generators(4)
Q = curve.scalar_mult(x, g1)
P = curve.scalar_mult(y, h1)