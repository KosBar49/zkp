import time
import pytest
from ..zkps.elliptic_curve import get_curve

X = 5
Y = 7
G = 2
H = 3

MODULO = 1019
XP = pow(G, X, MODULO)
XQ = pow(H, X, MODULO) #for test log equality
YQ = pow(H, Y, MODULO)

CURVE = get_curve('secp256r1')
G1C, H1C, G2C, H2C = CURVE.get_generators(4)

#secret 1
@pytest.fixture(scope="session")
def x():
    return 5

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



@pytest.fixture(autouse=True)
def time_test(request):
    start_time = time.time()
    # Yield to allow test execution to proceed
    yield
    # After the test has finished, calculate the time taken and print it
    duration = ( time.time() - start_time ) * 1000
    print(f"\n{request.node.name} took {duration:.2f} miliseconds to complete")