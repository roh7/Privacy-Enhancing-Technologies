#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py

#####################################################
# Group Members: Rohan Kopparapu, Jazib Mahboob
#####################################################

#####################################################
# IMPORTS
# T2
from os import urandom
from petlib.cipher import Cipher
# T3
from petlib.bn import Bn
# T4
from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify

#####################################################
# GLOBALS
aes = Cipher("aes-128-gcm")


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can
#           be imported.
# Status: DONE


#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.
# Status: DONE


def encrypt_message(K, message):
    """ Encrypt a message under a key K """
    plaintext = message.encode("utf8")
    iv = urandom(16)
    ciphertext, tag = aes.quick_gcm_enc(K, iv, plaintext)
    return (iv, ciphertext, tag)


def decrypt_message(K, iv, ciphertext, tag):
    """
    Decrypt a cipher text under a key K
    In case the decryption fails, throw an exception.
    """
    try:
        plain = aes.quick_gcm_dec(K, iv, ciphertext, tag)
    except:
        raise Exception("decryption failed")

    return plain.encode("utf8")


#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#    - Test if a point is on a curve.
#    - Implement Point addition.
#    - Implement Point doubling.
#    - Implement Scalar multiplication (double & add).
#    - Implement Scalar multiplication (Montgomery ladder).
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!
# Status: DONE


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:
              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)
    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) or (x is None and y is None)

    if x is None and y is None:
        return True

    lhs = (y * y) % p
    rhs = ((x * x * x) + (a * x) + b) % p
    on_curve = (lhs == rhs)

    return on_curve


def point_add(a, b, p, x0, y0, x1, y1):
    """
    Define the "addition" operation for 2 EC Points.
    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = yq - yp * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)
    Return the point resulting from the addition.
    Raises an Exception if the points are equal.
    """

    if ((x0, y0) == (x1, y1)):
        raise Exception('EC Points must not be equal')

    # if x1 == x0 then there is no inverse, also check both points are on curve
    if (x0 == x1) or (not is_point_on_curve(a, b, p, x0, y0)) or (not is_point_on_curve(a, b, p, x1, y1)):
        return(None, None)

    if (x0, y0) == (None, None):
        return (x1, y1)

    if (x1, y1) == (None, None):
        return (x0, y0)

    # calculate lam in stages using Bn methods
    xqminxp = x1.mod_sub(x0, p)
    yqminyp = y1.mod_sub(y0, p)

    xqminxpmodinv = xqminxp.mod_inverse(m=p)
    lam = xqminxpmodinv.mod_mul(yqminyp, p)

    # calculate xr
    lamsq = lam.mod_mul(lam, p)
    lamsqmin = lamsq.mod_sub(x0, p)
    xr = lamsqmin.mod_sub(x1, p)

    # calculate yr
    xpminxr = x0.mod_sub(xr, p)
    lamxpxr = lam.mod_mul(xpminxr, p)
    yr = lamxpxr.mod_sub(y0, p)

    return (xr, yr)


def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = 3 * xp ^ 2 + a * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """

    if x is None and y is None:
        return None, None

    xsq = x.mod_mul(x, p)
    xsq3 = Bn(3).mod_mul(xsq, p)
    num = xsq3.mod_add(a, p)
    y2 = Bn(2).mod_mul(y, p)
    y2inv = y2.mod_inverse(m=p)
    lam = num.mod_mul(y2inv, p)

    xr = lam.mod_mul(lam, p)
    xr = xr.mod_sub(x, p)
    xr = xr.mod_sub(x, p)

    yr = lam.mod_mul(x.mod_sub(xr, p), p)
    yr = yr.mod_sub(y, p)

    return (xr, yr)


def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of P == 1 then
                Q = Q + P
            P = 2 * P
        return Q
    """
    Q = (None, None)
    P = (x, y)
    binary = bin(scalar)

    for i in range(scalar.num_bits()):

        if binary[scalar.num_bits() - i + 1] == '1':
            Q = point_add(a, b, p, Q[0], Q[1], P[0], P[1])

        P = point_double(a, b, p, P[0], P[1])
    return Q


def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0
    """
    R0 = (None, None)
    R1 = (x, y)
    # convert the scalar variable to binary
    binary = bin(scalar)
    # start the scan checking each bit
    for i in reversed(range(0, scalar.num_bits())):
        # if bit is 0 do the addition and double R0
        if binary[scalar.num_bits() - i + 1] == '0':
            R1 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R0 = point_double(a, b, p, R0[0], R0[1])
        # if bit is not zero then do the addition and double R1
        else:
            R0 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R1 = point_double(a, b, p, R1[0], R1[1])
    return R0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#    - Implement a key / param generation
#    - Implement ECDSA signature using petlib.ecdsa
#    - Implement ECDSA signature verification
#      using petlib.ecdsa
# Status: DONE


def ecdsa_key_gen():
    """
    Returns an EC group, a random private key for signing
    and the corresponding public key for verification
    """
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)


def ecdsa_sign(G, priv_sign, message):
    """
    Sign the SHA256 digest of the message using ECDSA and return a signature
    """
    plaintext = message.encode("utf8")
    digest = sha256(plaintext).digest()
    sig = do_ecdsa_sign(G, priv_sign, digest)
    return sig


def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    plaintext = message.encode("utf8")
    digest = sha256(plaintext).digest()
    res = do_ecdsa_verify(G, pub_verify, sig, digest)
    return res

#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#    - use Bob's public key to derive a shared key.
#    - Use Bob's public key to encrypt a message.
#    - Use Bob's private key to decrypt the message.
# Status: DONE


def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    return (G, priv_dec, pub_enc)


def dh_encrypt(pub, message):
    """
    Assume you know the public key of someone else (Bob),
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message.
    """
    G, priv_key, pub_key = dh_get_key()
    assert G.check_point(pub)
    key = pub.pt_mul(priv_key)

    hashed_key = sha256(key.export()).digest()

    plaintext = message.encode("utf8")
    iv = urandom(16)

    cipher, tag = aes.quick_gcm_enc(hashed_key[:16], iv, plaintext)

    return (iv, cipher, tag, pub_key)


def dh_decrypt(priv, ciphertext):
    """
    Decrypt a received message encrypted using your public key,
    of which the private key is provided
    """
    # G, priv_key, pub_key = dh_get_key()

    iv, cipher, tag, pub_key = ciphertext

    shared_key = pub_key.pt_mul(priv)
    hashed_key = sha256(shared_key.export()).digest()

    plaintext = aes.quick_gcm_dec(hashed_key[:16], iv, cipher, tag)

    return plaintext.encode("utf8")

# NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py


test_G, test_priv_key, test_pub_key = dh_get_key()


def test_encrypt():
    """ Encrypts a message using the generated public key """
    message = u"i_need_about" * 350
    dh_encrypt(test_pub_key, message)
    assert True


def test_decrypt():
    """
    Decrypts the message using the generated private key
    Compares the decrypted message to the original message
    """
    message = u"i_need_about" * 350
    ciphertext = dh_encrypt(test_pub_key, message)
    assert dh_decrypt(test_priv_key, ciphertext) == message


def test_fails():
    """
    Attempts to decrypt the message only if the tags are valid
    """
    message = u"i_need_about" * 350
    orig_ciphertext = dh_encrypt(test_pub_key, message)
    iv, cipher, tag, pub_key = orig_ciphertext

    shared_key = pub_key.pt_mul(test_priv_key)
    hashed_key = sha256(shared_key.export()).digest()
    msg_encoded = message.encode("utf8")

    aes_gcm = Cipher.aes_128_gcm()
    enc_operation = aes_gcm.enc(hashed_key[:16], iv)
    enc_operation.update(msg_encoded)
    enc_operation.finalize()

    if tag == enc_operation.get_tag(16):
        assert dh_decrypt(test_priv_key, orig_ciphertext) == msg_encoded
    else:
        assert False

#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#    - Time your implementations of scalar multiplication
#      (use time.clock() for measurements)for different
#       scalar sizes)
#    - Print reports on timing dependencies on secrets.
#    - Fix one implementation to not leak information.
# Status: NO


def time_scalar_mul():
    pass

