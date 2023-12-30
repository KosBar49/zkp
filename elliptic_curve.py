import random
from libnum import ecc
from hashlib import sha512, sha256, md5, sha1

class EllipticCurve(ecc.Curve):

    supported_hash_functions = { 'md5' : md5, 'sha1' : sha1, 'sha256' : sha256, 'sha512' : sha512 }

    def __init__(self, type_, a, b, G, p, n):
        super().__init__(a, b, p, G, order=n)
        self._type = type_
        self.a = a
        self.b = b
        self.G = G
        self.p = p
        self.n = n

    # def __str__(self):
    #     return f"Curve: {self._type}\nParameters:\n a={self.a}\n b={self.b}\n G={self.G}\n p={self.p}\n n={self.n}"
    
    def get_generators(self, n = 1):
        
        gs = []
        G = self.g
        for _ in range(n):
            s = random.randint(0,self.n-1)
            gs.append(self.power(G, s))
        return gs
    
    def hash_list(self, list_, hash_function = 'sha1'):
        hash =  EllipticCurve.supported_hash_functions.get(hash_function, None)()
        if not hash:
            raise ValueError(f'Unsupported hash function: {hash_function}')
        for item in list_:
            
            hash.update(item)
        return int(hash.hexdigest(), 16)
    
    def hash_points(self, points):
        return self.hash_list([str(point).encode() for point in points])
    
    def get_random(self):
        return random.randint(0, self.n - 1)

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

    def scalar_mult(self, k, point):
        """Returns k * point computed using the double and point_add algorithm."""
        assert self.is_on_curve(point)

        if k % self.n == 0 or point is None:
            return None

        if k < 0:
            # k * point = -k * (-point)
            return self.scalar_mult(-k, self.point_neg(point))

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
    supported_curves = ['secp256k1', 'ed25519']
    curves = {
        "secp256k1": EllipticCurve(
            "secp256k1", 
            0, 
            7, 
            (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424), 
            115792089237316195423570985008687907853269984665640564039457584007908834671663, 
            115792089237316195423570985008687907852837564279074904382605163141518161494337
        ),
        "curve25519": EllipticCurve(
            "curve25519", 
            19298681539552699237261830834781317975544997444273427339909597334573241639236,
            55751746669818908907645289078257140818241103727901012315294400837956729358436,
            (19298681539552699237261830834781317975544997444273427339909597334652188435546, 14781619447589544791020593568409986887264606134616475288964881837755586237401),
            pow(2,255)-19,
            7237005577332262213973186563042994240857116359379907606001950938285454250989
        ),
    }
    if type_ in supported_curves:
        return curves.get(type_, None)
    else:
        raise ValueError(f"{type_} not supported")

# elif (mytype=="Curve25519"):
#   print ("Curve 25519 - Weierstrass")
#   a=19298681539552699237261830834781317975544997444273427339909597334573241639236
#   b=55751746669818908907645289078257140818241103727901012315294400837956729358436
#   G=(19298681539552699237261830834781317975544997444273427339909597334652188435546, 14781619447589544791020593568409986887264606134616475288964881837755586237401)
#   p=pow(2,255)-19
#   n=7237005577332262213973186563042994240857116359379907606001950938285454250989
# elif (mytype=="P192"):
#   print ("P192")
#   a=-3
#   b=18958286285566608000408668544493926415504680968679321075787234672564
#   G=(19277929113566293071110308034699488026831934219452440156649784352033, 19926808758034470970197974370888749184205991990603949537637343198772)
#   p=26959946667150639794667015087019630673557916260026308143510066298881
#   n=6277101735386680763835789423176059013767194773182842284081

# elif (mytype=="P512"):
#   print ("P512")
#   a=-3
#   b=1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984
#   G=(2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846, 3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784)
#   p=6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151
#   n=0x000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
# elif (mytype=="P256"):
#   print ("P256")
#   a=-3
#   b=41058363725152142129326129780047268409114441015993725554835256314039467401291
#   G=(48439561293906451759052585252797914202762949526041747995844080717082404635286, 36134250956749795798585127919587881956611106672985015071877198253568414405109)
#   p=115792089210356248762697446949407573530086143415290314195533631308867097853951
#   n=115792089210356248762697446949407573529996955224135760342422259061068512044369
# elif (mytype=="P224"):
#   print ("P224")
#   a=-3
#   b=18958286285566608000408668544493926415504680968679321075787234672564
#   G=(19277929113566293071110308034699488026831934219452440156649784352033, 19926808758034470970197974370888749184205991990603949537637343198772)
#   p=26959946667150639794667015087019630673557916260026308143510066298881
#   n=26959946667150639794667015087019625940457807714424391721682722368061
# elif (mytype=="P384"):
#   print ("P384")
#   a=-3
#   b=27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575
#   G=(26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087, 8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871)
#   p=39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
#   n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
# elif (mytype=="secp160r2"):
#   print ("secp160r2")
#   a=1461501637330902918203684832716283019651637554288
#   b=1032640608390511495214075079957864673410201913530
#   G=(0x52dcb034293a117e1f4ff11b30f7199d3144ce6d , 0xfeaffef2e331f296e071fa0df9982cfea7d43f2e)
#   p=1461501637330902918203684832716283019651637554291
#   n=1461501637330902918203685083571792140653176136043
# elif (mytype=="brainpoolP160r1"):
#   print ("brainpoolP160r1")
#   a=0x340E7BE2A280EB74E2BE61BADA745D97E8F7C300
#   b=0x1E589A8595423412134FAA2DBDEC95C8D8675E58
#   G=(0xBED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3, 0x1667CB477A1A8EC338F94741669C976316DA6321)
#   p=0xE95E4A5F737059DC60DFC7AD95B3D8139515620F
#   n=0xE95E4A5F737059DC60DF5991D45029409E60FC09
# elif (mytype=="brainpoolP192r1"):
#   print ("brainpoolP192r1")
#   a=0x6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF
#   b=0x469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9
#   G=(0xC0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6, 0x14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F)
#   p=0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297
#   n=0xC302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1
# elif (mytype=="brainpoolP224r1"):
#   print ("brainpoolP224r1")
#   a=0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43
#   b=0x2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B
#   G=(0x0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D,0x58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD)
#   p=0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF
#   n=0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F
# elif (mytype=="brainpoolP256r1"):
#   print ("brainpoolP256r1")
#   a=0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
#   b=0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
#   G=(0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262,0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997)
#   p=0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
#   n=0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
# elif (mytype=="BN(2,254)"):
#   print ("BN(2,254)")
#   a=0
#   b=2
#   G=(1,2)
#   p=0xfffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013 
#   n=0xfffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d
      