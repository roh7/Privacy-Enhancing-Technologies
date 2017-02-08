#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 02
#
# Basics of Mix networks and Traffic Analysis
#
# Run the tests through:
# $ py.test-2.7 -v Lab02Tests.py

#####################################################
# Group Members: Rohan Kopparapu, Diana Lee
#####################################################

#####################################################
# IMPORTS
# General
from collections import namedtuple
from hashlib import sha512
from struct import pack, unpack
from pprint import pprint
# T2
from petlib.ec import EcGroup
from petlib.hmac import Hmac, secure_compare
from petlib.cipher import Cipher
# T3
from petlib.ec import Bn
# T4
import random
from collections import Counter

#####################################################
# GLOBALS
aes = Cipher("AES-128-CTR")
to_print = False  # Disable stdout


def my_print(obj, pretty=False):
    if not to_print:
        return

    if pretty:
        pprint(obj)
    else:
        print(obj)

#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can
#           be imported.
# Status: DONE


#####################################################
# TASK 2 -- Build a simple 1-hop mix client.
#
# Status: DONE

def aes_ctr_enc_dec(key, iv, input):
    """
    A helper function that implements AES Counter (CTR)
        Mode encryption and decryption.
    Expects a key (16 byte), and IV (16 bytes) and an
        input plaintext / ciphertext.
    If it is not obvious convince yourself that CTR encryption
        and decryption are in fact the same operations.
    """
    enc = aes.enc(key, iv)
    output = enc.update(input)
    output += enc.finalize()
    return output


# This is the type of messages destined for the one-hop mix
OneHopMixMessage = namedtuple('OneHopMixMessage', ['ec_public_key',
                                                   'hmac',
                                                   'address',
                                                   'message'])


def mix_server_one_hop(private_key, message_list):
    """
    Implements the decoding for a simple one-hop mix.
    Each message is decoded in turn:
        - A shared key is derived from the message public key
            and the mix private_key.
        - the hmac is checked against all encrypted parts of the message
        - the address and message are decrypted, decoded and returned
    """
    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        # Check elements and lengths
        if (not G.check_point(msg.ec_public_key) or
                not len(msg.hmac) == 20 or
                not len(msg.address) == 258 or
                not len(msg.message) == 1002):
            raise Exception("Malformed input message")

        # First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # Check the HMAC
        h = Hmac(b"sha512", hmac_key)
        h.update(msg.address)
        h.update(msg.message)
        expected_mac = h.digest()

        if not secure_compare(msg.hmac, expected_mac[:20]):
            raise Exception("HMAC check failure")

        # Decrypt the address and the message
        iv = b"\x00" * 16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        # Decode the address and message
        address_len, address_full = unpack("!H256s", address_plaintext)
        message_len, message_full = unpack("!H1000s", message_plaintext)

        output = (address_full[:address_len], message_full[:message_len])
        out_queue += [output]

    return sorted(out_queue)


def mix_client_one_hop(public_key, address, message):
    """
    Encode a message to travel through a single mix with
        a set public key.
    The maximum size of the final address and the message
        are 256 bytes and 1000 bytes respectively.
    Returns an 'OneHopMixMessage' with four parts: a public
        key, an hmac (20 bytes), an address ciphertext
        (256 + 2 bytes) and a message ciphertext (1002 bytes).
    """

    G = EcGroup()
    assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # Use those as the payload for encryption
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    # Generate a fresh public key
    private_key = G.order().random()
    client_public_key = private_key * G.generator()

    # generate shared key and export
    shared_element = public_key.pt_mul(private_key)
    key_material = sha512(shared_element.export()).digest()

    # get hmac, address and message keys
    hmac_key = key_material[:16]
    address_key = key_material[16:32]
    message_key = key_material[32:48]

    # encode both address and message plaintexts
    iv = b"\x00" * 16
    address_cipher = aes_ctr_enc_dec(address_key, iv, address_plaintext)
    message_cipher = aes_ctr_enc_dec(message_key, iv, message_plaintext)

    # check the hmac and get expected mac
    h = Hmac(b"sha512", hmac_key)
    h.update(address_cipher)
    h.update(message_cipher)
    expected_mac = (h.digest())[:20]

    return OneHopMixMessage(client_public_key, expected_mac,
                            address_cipher, message_cipher)

#####################################################
# TASK 3 -- Build a n-hop mix client.
#           Mixes are in a fixed cascade.
# Status: DONE


# This is the type of messages destined for the n-hop mix
NHopMixMessage = namedtuple('NHopMixMessage', ['ec_public_key',
                                               'hmacs',
                                               'address',
                                               'message'])


def mix_server_n_hop(private_key, message_list, final=False):
    """
    Decodes a NHopMixMessage message and outputs either messages
        destined to the next mix or a list of tuples:
        (address, message) (if final=True)
        to be sent to their final recipients.

    Broadly speaking the mix will process each message in turn:
        - it derives a shared key (using its private_key),
        - checks the first hmac,
        - decrypts all other parts,
        - either forwards or decodes the message.
    """

    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        # Check elements and lengths
        if (not G.check_point(msg.ec_public_key) or
                not isinstance(msg.hmacs, list) or
                not len(msg.hmacs[0]) == 20 or
                not len(msg.address) == 258 or
                not len(msg.message) == 1002):
            raise Exception("Malformed input message")

        # First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # Extract a blinding factor for the public_key
        blinding_factor = Bn.from_binary(key_material[48:])
        new_ec_public_key = blinding_factor * msg.ec_public_key

        # Check the HMAC
        h = Hmac(b"sha512", hmac_key)

        for other_mac in msg.hmacs[1:]:
            h.update(other_mac)

        h.update(msg.address)
        h.update(msg.message)

        expected_mac = h.digest()

        if not secure_compare(msg.hmacs[0], expected_mac[:20]):
            raise Exception("HMAC check failure")

        # Decrypt hmacs
        new_hmacs = []
        for i, other_mac in enumerate(msg.hmacs[1:]):
            # Ensure the IV is different for each hmac
            iv = pack("H14s", i, b"\x00" * 14)
            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
            new_hmacs += [hmac_plaintext]

        # Decrypt address & message
        iv = b"\x00" * 16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        if final:
            # Decode the address and message
            address_len, address_full = unpack("!H256s", address_plaintext)
            message_len, message_full = unpack("!H1000s", message_plaintext)

            out_msg = (address_full[:address_len], message_full[:message_len])
            out_queue += [out_msg]
        else:
            # Pass the new mix message to the next mix
            out_msg = NHopMixMessage(new_ec_public_key, new_hmacs,
                                     address_plaintext, message_plaintext)
            out_queue += [out_msg]

    return out_queue


def mix_client_n_hop(public_keys, address, message):
    """
    Encode a message to travel through a sequence of mixes
        with a sequence public keys.
    The maximum size of the final address and the message are
        256 bytes and 1000 bytes respectively.
    Returns an 'NHopMixMessage' with four parts: a public key,
        a list of hmacs (20 bytes each),
    an address ciphertext (256 + 2 bytes) and a message
        ciphertext (1002 bytes).
    """
    G = EcGroup()
    # assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # use those encoded values as the payload you encrypt!
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    # Generate a fresh public key
    private_key = G.order().random()
    client_public_key = private_key * G.generator()

    # initialise ciphers
    address_cipher = address_plaintext
    message_cipher = message_plaintext

    # set blinding factor to 1
    blinding_factor = Bn(1)

    # initalise hmac and blinding key list with first public_key
    hmacs = []
    blinding_keys = []
    blinding_keys.append(public_keys[0])

    for i in range(1, len(public_keys)):
        # generate shared key and export
        shared_element = private_key * blinding_keys[-1]
        key_material = sha512(shared_element.export()).digest()

        # generate another blinding factor
        blinding_factor *= Bn.from_binary(key_material[48:])

        # append the calculated blinding key to list
        public_key = public_keys[i]
        blinding_keys.append(blinding_factor * public_key)

    # reverse list and traverse each hop using blinding factors
    blinding_keys = reversed(blinding_keys)
    for bk in blinding_keys:
        # generate shared key and export
        shared_element = private_key * bk
        key_material = sha512(shared_element.export()).digest()

        # get hmac, address and message keys
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # encode both address and message plaintexts
        iv = b"\x00" * 16
        address_cipher = aes_ctr_enc_dec(address_key, iv, address_cipher)
        message_cipher = aes_ctr_enc_dec(message_key, iv, message_cipher)

        # intiialise a temporary Hmac and list of hmacs
        h = Hmac(b"sha512", hmac_key)
        temp_hmacs = []

        for i in range(len(hmacs)):
            prev_mac = hmacs[i]
            # use a different iv for each hmac
            iv = pack("H14s", i, b"\x00" * 14)

            # encode hmac plaintext and add to temp list
            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, prev_mac)
            h.update(hmac_plaintext)
            temp_hmacs += [hmac_plaintext]

        h.update(address_cipher)
        h.update(message_cipher)

        # check the hmac and prepend expected mac to temp list
        expected_mac = h.digest()[:20]
        temp_hmacs = [expected_mac] + temp_hmacs

        hmacs = temp_hmacs

    return NHopMixMessage(client_public_key, hmacs,
                          address_cipher, message_cipher)

#####################################################
# TASK 4 -- Statistical Disclosure Attack
#           Given a set of anonymized traces
#           the objective is to output an ordered list
#           of likely `friends` of a target user.
# Status: DONE


def generate_trace(number_of_users, threshold_size, number_of_rounds,
                   targets_friends):
    """ Generate a simulated trace of traffic. """
    others = range(1, number_of_users)
    all_users = range(number_of_users)

    trace = []
    # Generate traces in which Alice (user 0) is not sending
    for _ in range(number_of_rounds // 2):
        senders = sorted(random.sample(others, threshold_size))
        receivers = sorted(random.sample(all_users, threshold_size))

        trace += [(senders, receivers)]

    # Generate traces in which Alice (user 0) is sending
    for _ in range(number_of_rounds // 2):
        senders = sorted([0] + random.sample(others,
                                             threshold_size - 1))
        # Alice sends to a friend
        friend = random.choice(targets_friends)
        receivers = sorted([friend] + random.sample(all_users,
                                                    threshold_size - 1))

        trace += [(senders, receivers)]

    random.shuffle(trace)
    return trace


def analyze_trace(trace, target_number_of_friends, target=0):
    """
    Given a trace of traffic, and a given number of friends,
    return the list of receiver identifiers that are the most
    likely friends of the target.
    """
    # Counter for when target is in senders list
    receivers_target = Counter()

    # Counter for when Alice isn't in the senders list
    receivers_not_target = Counter()

    # Counter to check difference in counts for each receiver
    diff_receivers = Counter()

    # Count when the receiver was referenced
    for t in trace:
        senders, receivers = t
        if target in senders:
            for r in receivers:
                receivers_target[r] += 1
        else:
            for r in receivers:
                receivers_not_target[r] += 1

    # Process receiver counters
    receivers_target_list = list(receivers_target)
    for r in receivers_target_list:
        data = {"receiver": r,
                "target count": receivers_target[r],
                "non target count": receivers_not_target[r]}
        my_print(data, pretty=True)
        diff_receivers[r] = receivers_target[r] - receivers_not_target[r]

    # Construct list for results and target's most common friends
    results = []
    target_common = list(diff_receivers.most_common(target_number_of_friends))

    # create and return list of most likely friends of the target
    for counter in target_common:
        identifier, count = counter
        results.append(identifier)

    return results

#####################################################
# TASK Q1 (Question 1):
#   The mix packet format you worked on uses AES-CTR
#       with an IV set to all zeros.
#   Explain whether this is a security concern and justify
#       your answer.
# Status: DONE


"""
This would cause a serious security concern ** IF ** both the key and
    the IV were reproduced and used in encryption of another message,
    and so would cause problems if by some chance, the same private key
    is reproduced by our pseudo-random number generator. Such a
    situation would allow an adversary to undermine the secrecy of our
    implementation.
As a repeated or constant IV means the probability of a repeated counter
    value may not be negligible, and we cannot assume that the same
    private key will never be reproduced, our implementation could
    therefore be improved; it's not completely insecure but could be
    better.
In this case, the IV value was set to zeros ** before ** the encryption
    was executed, and as our implementation is solely in *using* the
    OpenSSL algorithm, we can assume the counter value should increment
    properly, where a counter value is never repeated and is handled by
    the algorithm, not us - a black box situation.
The implementation is not fail-safe as we are dependent on the algorithm
    to 'play safe' for us. We should thus improve our implementation by
    using a newly generated 16-byte random IV for each message, and
    ensuring that the private key is produced by a cryptographically
    secure PRG.
"""

#####################################################
# TASK Q2 (Question 2):
# What assumptions does your implementation of the
#   Statistical Disclosure Attack makes about the
#   distribution of traffic from non-target senders
#   to receivers?
# Is the correctness of the result returned dependent
#   on this background distribution?
# Status: DONE


"""
Assumptions made about the background distribution are as follows:
    1) it occurs in discrete time
    2) it is independent from the target traffic surrounding our target
    sender
    3) it and the target distribution both fulfill the Markov property
    and create time-homogenous Markov chains where the conditional
    probability of the subsequent events do not depend on the current
    time unit.
Yes, the correctness is dependent on the background distribution and
    target distribution being independent, and relies on the assumption
    that they both fulfill the Markov and time-homogenous properties.
"""

