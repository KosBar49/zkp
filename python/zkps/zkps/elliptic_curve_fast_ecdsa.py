import random
from libnum import ecc
from hashlib import sha512, sha256, md5, sha1


class EllipticCurve(ecc.Curve):

    supported_hash_functions = {
        'md5': md5, 'sha1': sha1, 'sha256': sha256, 'sha512': sha512}

    def __init__(self, type_, a, b, G, p, n, hash_function='sha256'):
        super().__init__(a, b, p, G, order=n)
        self._type = type_
        self.a = a
        self.b = b
        self.G = G
        self.p = p
        self.n = n
        self._hash_function = hash_function
        self._random = random.SystemRandom()

    # def __str__(self):
    #     return f"Curve: {self._type}\nParameters:\n a={self.a}\n b={self.b}\n G={self.G}\n p={self.p}\n n={self.n}"

    def get_generators(self, n=1):

        gs = []
        G = self.g
        for _ in range(n):
            s = self._random.randint(0, self.n-1)
            gs.append(self.power(G, s))
        return gs

    def hash_list(self, list_):
        hash = EllipticCurve.supported_hash_functions.get(
            self._hash_function, None)()
        if not hash:
            raise ValueError(f'Unsupported hash function: {self._hash_function}')
        for item in list_:
            #print(f"hashing {item}")
            hash.update(item)
        return int(hash.hexdigest(), 16)

    def hash_points(self, points):
        return self.hash_list([str(point).encode() for point in points])

    def get_random(self):
        return self._random.randint(0, self.n - 1)

    def inverse_mod(self, k, p):
        """Returns the inverse of k modulo p.
        This function returns the only integer x such that (x * k) % p == 1.
        k must be non-zero and p must be a prime.
        """
        if k == 0:
            raise ZeroDivisionError('division by zero')

        if k < 0:
            # k ** -1 = p - (-k) ** -1  (mod p)
            return p - self.inverse_mod(-k, p)

        # Extended Euclidean algorithm.
        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = p, k

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        gcd, x, _ = old_r, old_s, old_t

        assert gcd == 1
        assert (k * x) % p == 1

        return x % p

    def point_add(self, point1, point2):
        """Returns the result of point1 + point2 according to the group law."""
        assert self.is_on_curve(point1)
        assert self.is_on_curve(point2)

        if point1 is None:
            # 0 + point2 = point2
            return point2
        if point2 is None:
            # point1 + 0 = point1
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 != y2:
            # point1 + (-point1) = 0
            return None

        if x1 == x2:
            # This is the case point1 == point2.
            m = (3 * x1 * x1 + self.a) * self.inverse_mod(2 * y1, self.p)
        else:
            # This is the case point1 != point2.
            m = (y1 - y2) * self.inverse_mod(x1 - x2, self.p)

        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)
        result = (x3 % self.p, -y3 % self.p)

        assert self.is_on_curve(result)

        return result

    def is_on_curve(self, point):
        """Returns True if the given point lies on the elliptic curve."""
        if point is None:
            # None represents the point at infinity.
            return True
        x, y = point

        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def mult_point(self, k, point):
        """Returns k * point computed using the double and point_add algorithm."""
        assert self.is_on_curve(point)

        if k % self.n == 0 or point is None:
            return None

        if k < 0:
            # k * point = -k * (-point)
            return self.mult_point(-k, self.point_neg(point))

        result = None
        addend = point

        while k:
            if k & 1:
                # Add.
                result = self.point_add(result, addend)

            # Double.
            addend = self.point_add(addend, addend)

            k >>= 1

        assert self.is_on_curve(result)

        return result

    def point_neg(self, point):
        """Returns -point."""
        assert self.is_on_curve(point)

        if point is None:
            # -0 = 0
            return None

        x, y = point
        result = (x, -y % self.p)

        assert self.is_on_curve(result)

        return result


def get_curve(type_):
    supported_curves = ['secp256k1', "secp256r1", 'P192']
    curves = {
        "secp256k1": EllipticCurve(
            "secp256k1",
            0,
            7,
            (55066263022277343669578718895168534326250603453777594175500187360389116729240,
             32670510020758816978083085130507043184471273380659243275938904335757337482424),
            115792089237316195423570985008687907853269984665640564039457584007908834671663,
            115792089237316195423570985008687907852837564279074904382605163141518161494337
        ),
        "secp256r1": EllipticCurve(
            "secp256r1",
            0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
            0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
            (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 
             0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
            0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
            115792089210356248762697446949407573529996955224135760342422259061068512044369
        ),
        "curve25519": EllipticCurve(
            "curve25519",
            19298681539552699237261830834781317975544997444273427339909597334573241639236,
            55751746669818908907645289078257140818241103727901012315294400837956729358436,
            (19298681539552699237261830834781317975544997444273427339909597334652188435546,
             14781619447589544791020593568409986887264606134616475288964881837755586237401),
            pow(2, 255)-19,
            7237005577332262213973186563042994240857116359379907606001950938285454250989
        ),
        "P192": EllipticCurve(
            "P192",
            -3,
            18958286285566608000408668544493926415504680968679321075787234672564,
            (19277929113566293071110308034699488026831934219452440156649784352033,
             19926808758034470970197974370888749184205991990603949537637343198772),
            26959946667150639794667015087019630673557916260026308143510066298881,
            6277101735386680763835789423176059013767194773182842284081
        ),
        "P512": EllipticCurve(
            "P512",
            -3,
            1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984,
            (2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846,
             3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784),
            6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151,
            0x000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
        ), 
    }
    if type_ in supported_curves:
        return curves.get(type_, None)
    else:
        raise ValueError(f"{type_} not supported")
