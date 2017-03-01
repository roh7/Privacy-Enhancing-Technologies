#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 03
#
# Basics of Privacy Friendly Computations through
#         Additive Homomorphic Encryption.
#
# Run the tests through:
# $ py.test-2.7 -v Lab03Tests.py

#####################################################
# Group Members: Rohan Kopparapu, Ayana Matsui
#####################################################

#####################################################
# IMPORTS
# General
from petlib.ec import EcGroup

#####################################################
# TASK 1 -- Setup, key derivation, log
#           Encryption and Decryption
#
# Status: DONE


def setup():
    """Generates the Cryptosystem Parameters."""
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    o = G.order()
    return (G, g, h, o)


def keyGen(params):
    """ Generate a private / public key pair """
    (G, g, h, o) = params
    priv = o.random()
    pub = priv * g
    return (priv, pub)


def encrypt(params, pub, m):
    """ Encrypt a message under the public key """
    if not -100 < m < 100:
        raise Exception("Message value to low or high.")

    (G, g, h, o) = params
    priv = o.random()
    a = priv * g
    b = priv * pub + m * h
    return (a, b)


def isCiphertext(params, ciphertext):
    """ Check a ciphertext """
    (G, g, h, o) = params
    ret = len(ciphertext) == 2
    a, b = ciphertext
    ret &= G.check_point(a)
    ret &= G.check_point(b)
    return ret


_logh = None


def logh(params, hm):
    """ Compute a discrete log, for small number only """
    global _logh
    (G, g, h, o) = params

    # Initialize the map of logh
    if _logh is None:  # or ==
        _logh = {}
        for m in range(-1000, 1000):
            _logh[(m * h)] = m

    if hm not in _logh:
        raise Exception("No decryption found.")

    return _logh[hm]


def decrypt(params, priv, ciphertext):
    """ Decrypt a message using the private key """
    assert isCiphertext(params, ciphertext)
    a, b = ciphertext
    a = priv * a
    hm = b - a
    return logh(params, hm)

#####################################################
# TASK 2 -- Define homomorphic addition and
#           multiplication with a public value
#
# Status: DONE


def add(params, pub, c1, c2):
    """
    Given two ciphertexts compute the ciphertext of the
    sum of their plaintexts.
    """
    assert isCiphertext(params, c1)
    assert isCiphertext(params, c2)

    (G, g, h, o) = params
    (m0, k0) = c1
    (m1, k1) = c2
    c3 = (m0 + m1, k0 + k1)

    return c3


def mul(params, pub, c1, alpha):
    """
    Given a ciphertext compute the ciphertext of the
    product of the plaintext time alpha
    """
    assert isCiphertext(params, c1)

    (G, g, h, o) = params
    (a0, b0) = c1
    c3 = (a0.pt_mul(alpha), b0.pt_mul(alpha))

    return c3

#####################################################
# TASK 3 -- Define Group key derivation & Threshold
#           decryption. Assume an honest but curious
#           set of authorities.
# Status: DONE


def groupKey(params, pubKeys=[]):
    """ Generate a group public key from a list of public keys """
    (G, g, h, o) = params

    pub = pubKeys[0]

    for k in pubKeys[1:]:
        pub += k

    return pub


def partialDecrypt(params, priv, ciphertext, final=False):
    """
    Given a ciphertext and a private key, perform partial decryption.
    If final is True, then return the plaintext.
    """
    assert isCiphertext(params, ciphertext)

    (a, b) = ciphertext
    a1 = priv * a
    b1 = b - a1

    if final:
        return logh(params, b1)
    else:
        return a, b1

#####################################################
# TASK 4 -- Actively corrupt final authority, derives
#           a public key with a known private key.
#
# Status: DONE


def corruptPubKey(params, priv, OtherPubKeys=[]):
    """
    Simulate the operation of a corrupt decryption authority.
    Given a set of public keys from other authorities return a
    public key for the corrupt authority that leads to a group
    public key corresponding to a private key known to the
    corrupt authority.
    """
    (G, g, h, o) = params

    pub = OtherPubKeys[0]
    pub = -pub

    for k in OtherPubKeys[1:]:
        pub += -k

    own_key = priv * g
    pub += own_key

    return pub

#####################################################
# TASK 5 -- Implement operations to support a simple
#           private poll.
#
# Status: DONE


def encode_vote(params, pub, vote):
    """
    Given a vote 0 or 1 encode the vote as two
    ciphertexts representing the count of votes for
    zero and the votes for one.
    """
    assert vote in [0, 1]

    v0 = encrypt(params, pub, (1 - vote))
    v1 = encrypt(params, pub, vote)
    return (v0, v1)


def process_votes(params, pub, encrypted_votes):
    """
    Given a list of encrypted votes tally them
    to sum votes for zeros and votes for ones.
    """
    assert isinstance(encrypted_votes, list)
    tv0, tv1 = encrypted_votes[0]

    for (i, j) in encrypted_votes[1:]:
        tv0 = add(params, pub, i, tv0)
        tv1 = add(params, pub, j, tv1)

    return tv0, tv1


def simulate_poll(votes):
    """
    Simulates the full process of encrypting votes,
    tallying them, and then decrypting the total.
    """

    # Generate parameters for the crypto-system
    params = setup()

    # Make keys for 3 authorities
    priv1, pub1 = keyGen(params)
    priv2, pub2 = keyGen(params)
    priv3, pub3 = keyGen(params)
    pub = groupKey(params, [pub1, pub2, pub3])

    # Simulate encrypting votes
    encrypted_votes = []
    for v in votes:
        encrypted_votes.append(encode_vote(params, pub, v))

    # Tally the votes
    total_v0, total_v1 = process_votes(params, pub, encrypted_votes)

    # Simulate threshold decryption
    privs = [priv1, priv2, priv3]
    for priv in privs[:-1]:
        total_v0 = partialDecrypt(params, priv, total_v0)
        total_v1 = partialDecrypt(params, priv, total_v1)

    total_v0 = partialDecrypt(params, privs[-1], total_v0, True)
    total_v1 = partialDecrypt(params, privs[-1], total_v1, True)

    # Return the plaintext values
    return total_v0, total_v1

###########################################################
# TASK Q1 -- Answer questions regarding your implementation
#
# Consider the following game between an adversary A and honest users
#   H1 and H2:
# 1) H1 picks 3 plaintext integers Pa, Pb, Pc arbitrarily, and encrypts
#   them to the public key of H2 using the scheme you defined in TASK 1.
# 2) H1 provides the ciphertexts Ca, Cb and Cc to H2 who flips a fair
#   coin b.
#    In case b=0 then H2 homomorphically computes C as the encryption
#       of Pa plus Pb.
#    In case b=1 then H2 homomorphically computes C as the encryption
#       of Pb plus Pc.
# 3) H2 provides the adversary A, with Ca, Cb, Cc and C.
#
# What is the advantage of the adversary in guessing b given your
#   implementation of Homomorphic addition? What are the security
#   implications of this?


"""
The adversary has an almost certain advantage as to guessing b, assuming that he has the
    ability to do homomorphic operation. Our implementation is simply an addition of the
    two ciphertexts.
If the adversary can perform C-Cb, then they can compare the result with Ca and Cc. The
    security implication of this is that it is easy to apply and de-apply homomorphic
    operations if the original equations and values are know.
However, if the equations are complex enough, or the adversary does not know them, they
    cannot find the contents of result(C).
At the same time, the notion of being able to guess b does not imply anything about being
    able to guess the plaintext from our ciphertext.
"""

###########################################################
# TASK Q2 -- Answer questions regarding your implementation
#
# Given your implementation of the private poll in TASK 5, how
# would a malicious user implement encode_vote to (a) distrupt the
# poll so that it yields no result, or (b) manipulate the poll so
# that it yields an arbitrary result. Can those malicious actions
# be detected given your implementation?


"""
a) The adversary could disrupt (i.e. cause the system to show illogical votes) by simply
    modifying the number of votes in the encode_vote() method. Since we are encrypting
    and counting the votes, they can change the code and increase the vote count,
    resulting in an unusable outcome.
b) While we couldn\'t think of a way to manipulate in a completely arbitrary way, the
    adversary could partially affect the result. Let us assume that the adversary wants
    an 85:15, v0 to v1 ratio, they can implement a random of 1-100, where if the value is
    equal to or under 85, the vote goes to v0, else goes to v1. The adversary could get
    unlucky if the number of votes is small, but could work if there are many votes.
   Alternatively, the adversary could generate private keys and make up votes to
    manipulate the votes and get the arbitrary result they wish. Since the implementation
    does not verify user identities, it is possible to vote multiple times with multiple
    keys.
"""

