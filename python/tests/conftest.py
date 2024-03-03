import pytest

X = 5
Y = 7
G = 2
H = 3
MODULO = 1019
XP = pow(G, X, MODULO)
XQ = pow(H, X, MODULO) #for test log equality
YQ = pow(H, Y, MODULO)

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