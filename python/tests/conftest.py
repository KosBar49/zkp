from socket import SocketIO
import time
import pytest
from ..zkps.elliptic_curve import get_curve

X = 5
Y = 7
G = 2
H = 3
G2 = 5
H2 = 7

MODULO = 1019
XP = pow(G, X, MODULO)
XQ = pow(H, X, MODULO) #for test log equality
YQ = pow(H, Y, MODULO)

CURVE = get_curve('secp256r1')
G1C, H1C, G2C, H2C = CURVE.get_generators(4)
XPC = CURVE.scalar_mult(X, G1C)
YQC = CURVE.scalar_mult(Y, H1C)

#secret 1
@pytest.fixture(scope="session")
def x():
    return 5

@pytest.fixture(scope="session")
def g2():
    return G2

@pytest.fixture(scope="session")
def h2():
    return H2 
 
#sectret 2
@pytest.fixture(scope="session") 
def y():
    return 7

# generator
@pytest.fixture(scope="session") 
def g():
    return G

# generator 2
@pytest.fixture(scope="session") 
def h():
    return H

# g^x
@pytest.fixture(scope="session") 
def P():
    return XP

@pytest.fixture(scope="session") 
def xQ():
    return XQ

# h^y
@pytest.fixture(scope="session") 
def Q():
    return YQ

# modulo
@pytest.fixture(scope="session") 
def p():
    return MODULO

# h^y
@pytest.fixture(scope="session") 
def g1c():
    return G1C

# h^y
@pytest.fixture(scope="session") 
def h1c():
    return H1C

# h^y
@pytest.fixture(scope="session") 
def g2c():
    return G2C

# h^y
@pytest.fixture(scope="session") 
def h2c():
    return H2C

# P value for most of the ecc tests, c is shortcut for ecc
@pytest.fixture(scope="session")
def PC():
    return XPC

# Q value for most of the ecc tests, c is shortcut for ecc  
@pytest.fixture(scope="session")
def QC():
    return YQC

# P value for pederesen commitment ECC test
@pytest.fixture(scope="session")
def p_ecc_pederesen_commitment():
    return CURVE.point_add(CURVE.scalar_mult(X, G1C), CURVE.scalar_mult(Y, H1C))

@pytest.fixture(scope="session")
def p_test_pederesnen_commitment_eq_message_randomness():
    return (pow(G, X, MODULO) * pow(H, Y, MODULO)) % MODULO

@pytest.fixture(scope="session")
def q_test_pederesnen_commitment_eq_message_randomness():
    return (pow(G2, X, MODULO) * pow(H2, Y, MODULO)) % MODULO    

@pytest.fixture(autouse=True)
def time_test(request):
    start_time = time.time()
    # Yield to allow test execution to proceed
    yield
    # After the test has finished, calculate the time taken and print it
    duration = ( time.time() - start_time ) * 1000
    print(f"\n{request.node.name} took {duration:.2f} miliseconds to complete")