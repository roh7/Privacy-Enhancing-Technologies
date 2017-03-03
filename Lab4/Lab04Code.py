#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 04
#
# Zero Knowledge Proofs
#
# Run the tests through:
# $ py.test -v Lab04Tests.py

#####################################################
# Group Members: Rohan Kopparapu, Mark Daniels
#####################################################

#####################################################
# IMPORTS
# General
from petlib.ec import EcGroup
from petlib.bn import Bn
from hashlib import sha256
from binascii import hexlify


def setup():
    """ Generates the Cryptosystem Parameters. """
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    hs = [G.hash_to_point(("h%s" % i).encode("utf8")) for i in range(4)]
    o = G.order()
    return (G, g, hs, o)


def keyGen(params):
    """ Generate a private / public key pair. """
    (G, g, hs, o) = params
    priv = o.random()
    pub = priv * g
    return (priv, pub)


def to_challenge(elements):
    """ Generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash = sha256(Cstring).digest()
    return Bn.from_binary(Chash)

#####################################################
# TASK 1 -- Prove knowledge of a DH public key's
#           secret.
#
# Status: DONE


def proveKey(params, priv, pub):
    """
    Uses the Schnorr non-interactive protocols produce a proof
    of knowledge of the secret priv such that pub = priv * g.

    Outputs: a proof (c, r)
             c (a challenge)
             r (the response)
    """
    (G, g, hs, o) = params

    # generate random key
    w = o.random()
    W = w * g

    # compute challenge and response
    c = to_challenge([g, W])
    r = (w - (c * priv)) % o

    return (c, r)


def verifyKey(params, pub, proof):
    """
    Schnorr non-interactive proof verification of knowledge of a secret
    Returns a boolean indicating whether the verification was successful
    """
    (G, g, hs, o) = params
    c, r = proof
    gw_prime = c * pub + r * g
    return to_challenge([g, gw_prime]) == c

#####################################################
# TASK 2 -- Prove knowledge of a Discrete Log
#           representation.
#
# Status: TODO


def commit(params, secrets):
    """
    Produces a commitment C = r * g + Sum xi * hi, where secrets is a
        list of xi of length 4.
    Returns the commitment (C) and the opening (r).
    """
    assert len(secrets) == 4
    (G, g, (h0, h1, h2, h3), o) = params
    x0, x1, x2, x3 = secrets
    r = o.random()
    C = x0 * h0 + x1 * h1 + x2 * h2 + x3 * h3 + r * g
    return (C, r)


def proveCommitment(params, C, r, secrets):
    """
    Prove knowledge of the secrets within a commitment, as well as the
            opening of the commitment.

    Args: C (the commitment), r (the opening of the
            commitment), and secrets (a list of secrets).
    Returns: a challenge (c) and a list of responses.
    """
    (G, g, (h0, h1, h2, h3), o) = params
    x0, x1, x2, x3 = secrets

    # YOUR CODE HERE:
    c = None
    responses = None

    return (c, responses)


def verifyCommitments(params, C, proof):
    """
    Verify a proof of knowledge of the commitment.
    Return a boolean denoting whether the verification succeeded.
    """
    (G, g, (h0, h1, h2, h3), o) = params
    c, responses = proof
    (r0, r1, r2, r3, rr) = responses

    Cw_prime = c * C + r0 * h0 + r1 * h1 + r2 * h2 + r3 * h3 + rr * g
    c_prime = to_challenge([g, h0, h1, h2, h3, Cw_prime])
    return c_prime == c

#####################################################
# TASK 3 -- Prove Equality of discrete logarithms.
#
# Status: TODO


def gen2Keys(params):
    """ Generate two related public keys K = x * g and L = x * h0. """
    (G, g, (h0, h1, h2, h3), o) = params
    x = o.random()

    K = x * g
    L = x * h0

    return (x, K, L)


def proveDLEquality(params, x, K, L):
    """
    Generate a ZK proof that two public keys K, L have the same secret
    private key x, as well as knowledge of this private key.
    """
    (G, g, (h0, h1, h2, h3), o) = params
    w = o.random()
    Kw = w * g
    Lw = w * h0

    c = to_challenge([g, h0, Kw, Lw])

    r = (w - c * x) % o
    return (c, r)


def verifyDLEquality(params, K, L, proof):
    """
    Return whether the verification of equality of two discrete
        logarithms succeeded.
    """
    (G, g, (h0, h1, h2, h3), o) = params
    c, r = proof

    # YOUR CODE HERE:
    something = None

    return something  # YOUR RETURN HERE

#####################################################
# TASK 4 -- Prove correct encryption and knowledge of
#           a plaintext.
#
# Status: TODO


def encrypt(params, pub, m):
    """
    Encrypt a message m under a public key pub.
    Returns both the randomness and the ciphertext.
    """
    (G, g, (h0, h1, h2, h3), o) = params
    k = o.random()
    return k, (k * g, k * pub + m * h0)


def proveEnc(params, pub, Ciphertext, k, m):
    """
    Prove in ZK that the ciphertext is well formed and knowledge of the
        message encrypted as well.
    Return the proof: challenge and the responses.
    """
    (G, g, (h0, h1, h2, h3), o) = params
    a, b = Ciphertext

    # YOUR CODE HERE:
    c = None
    rk = None
    rm = None

    return (c, (rk, rm))


def verifyEnc(params, pub, Ciphertext, proof):
    """
    Verify the proof of correct encryption and knowledge of a ciphertext
    """
    (G, g, (h0, h1, h2, h3), o) = params
    a, b = Ciphertext
    (c, (rk, rm)) = proof

    # YOUR CODE HERE:
    something = None

    return something  # YOUR RETURN HERE

#####################################################
# TASK 5 -- Prove a linear relation
#
# Status: TODO


def relation(params, x1):
    """
    Returns a commitment C to x0 and x1, such that x0 = 10 x1 + 20, as
        well as x0, x1 and the commitment opening r.
    """
    (G, g, (h0, h1, h2, h3), o) = params
    r = o.random()

    x0 = (10 * x1 + 20)
    C = r * g + x1 * h1 + x0 * h0

    return C, x0, x1, r


def prove_x0eq10x1plus20(params, C, x0, x1, r):
    """
    Prove C is a commitment to x0 and x1 and that x0 = 10 x1 + 20.
    """
    (G, g, (h0, h1, h2, h3), o) = params

    # YOUR CODE HERE:
    something = None

    return something  # YOUR RETURN HERE


def verify_x0eq10x1plus20(params, C, proof):
    """ Verify that proof of knowledge of C and x0 = 10 x1 + 20. """
    (G, g, (h0, h1, h2, h3), o) = params

    # YOUR CODE HERE:
    something = None

    return something  # YOUR RETURN HERE

#####################################################
# TASK 6 -- (OPTIONAL) Prove that a ciphertext is either 0 or 1
#
# Status: Nah


def binencrypt(params, pub, m):
    """ Encrypt a binary value m under public key pub """
    assert m in [0, 1]
    (G, g, (h0, h1, h2, h3), o) = params

    k = o.random()
    return k, (k * g, k * pub + m * h0)


def provebin(params, pub, Ciphertext, k, m):
    """
    Prove a ciphertext is valid and encrypts a binary value either
        0 or 1.
    """
    pass


def verifybin(params, pub, Ciphertext, proof):
    """ verify that proof that a cphertext is a binary value 0 or 1. """
    pass


def test_bin_correct():
    """ Test that a correct proof verifies """
    pass


def test_bin_incorrect():
    """ Prove that incorrect proofs fail. """
    pass

