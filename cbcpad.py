# This file is licensed under the terms of the MIT license.
# See the LICENSE file in the root of this repository for complete details.
"""Padding oracle attack on CBC with PKCS7 padding"""

import logging

__all__ = ["decrypt"]

log = logging.getLogger(__name__)


def co_repeat(func):
    # Yields the result of calling func with the argument that were last sent.

    arg = yield

    while True:
        arg = yield func(arg)


def co_plug(gen1, gen2):
    # Plugs two generators by repeatedly sending what the first one yields two the
    # second one and then what the second one yields to the first one, until the
    # first one stops.

    has_msg = False
    msg = None
    for msg in gen1:
        has_msg = True
        break

    if not has_msg:
        return None

    for _ in gen2:
        break

    while True:
        res = gen2.send(msg)
        try:
            msg = gen1.send(res)
        except StopIteration as e:
            return e.value


def prepare_extended_pad(ctext, length, block_pos):
    # Prepares the second-to-last block in order to extend the fake
    # padding in the last block, so that an oracle can verify the result
    # and confirm the padding.
    #
    # ctext is a bytearray of the cipher text with fake padding.
    # Mutated in place.
    # length is the length of the current fake padding (possibly 0).
    # block_pos is the position of the block to be modified for creating
    # the fake padding, counter from the last byte.
    # bs is the block size.

    stop = len(ctext) - block_pos
    for i in range(stop - length, stop):
        ctext[i] ^= length ^ (length + 1)

    return ctext


def possible_extended_pads(ctext, length, block_pos, possible_bytes):
    # Generates all possible extended pads
    #
    # ctext is mutated in place.

    prepare_extended_pad(ctext, length, block_pos)
    for byte in possible_bytes:
        ctext[len(ctext) - block_pos - length - 1] = byte

        yield ctext


def decrypt_block(ctext, ptext, block_pos, bs, last_unchanged=False):
    # Generates possible pads for a given block and extends them when
    # they are correct.
    #
    # ctext is mutated in place.

    stop = len(ctext) - block_pos
    original_block = ctext[stop - bs: stop]

    log.info('block_pos=%r', block_pos//bs)
    for length in range(bs):
        if block_pos == bs and length == 0:
            last_byte = ctext[stop - 1]
            if last_unchanged:
                # In this case the padding is 0x01.
                possible_bytes = (last_byte,)
            else:
                # If leave the byte unchanged the padding will be correct
                # but it will not be 0x01.
                possible_bytes = (x for x in range(256) if x != last_byte)
        else:
            possible_bytes = range(256)

        ct = ctext
        for ct in possible_extended_pads(ctext, length, block_pos, possible_bytes):
            pad_is_good = yield ct
            if pad_is_good:
                pt_block = bytearray(
                    x ^ (length + 1) ^ original_block[i + bs - length - 1]
                    for i, x in enumerate(ct[stop - length - 1 : stop])
                )
                log.debug('block=%r', pt_block)

                if block_pos == bs and not verify_pad(pt_block, bs):
                    raise RuntimeError("Bad pad decrypted")
                break

        if not pad_is_good:
            raise ValueError("No good pad found")

    for i in range(stop - bs, stop):
        original_byte = original_block[i - stop + bs]

        # Store decrypted block.
        ptext[i] = ct[i] ^ bs ^ original_byte

        # Eliminate fake pad when done.
        ct[i] = original_byte

    return ct, ptext


def decryptor(ctext, bs, last_unchanged=False):
    def truncated(block_pos, pads):
        pad_is_good = None
        while True:
            try:
                # Get the ciphertext to try for obtaining a valid padding.
                # One tries to get a longer padding after succeeding in obtaining a
                # valid padding.
                c = pads.send(pad_is_good)

                # Truncate the cipher text until the block where the padding appears.
                pad_is_good = yield bytes(c[:len(c)-block_pos+bs])
            except StopIteration as e:
                log.info('block=%r', e.value[1]) # pylint: disable=unsubscriptable-object
                return e.value

    assert len(ctext) % bs == 0
    ctext = bytearray(ctext)
    ptext = bytearray(len(ctext) - bs)

    for block_pos in range(bs, len(ctext), bs):
        ctext, ptext = yield from truncated(
            block_pos,
            decrypt_block(ctext, ptext, block_pos, bs, last_unchanged)
        )

    return bytes(ptext)


def verify_pad(ct, bs):
    length = ct[-1]
    return 0 < length <= bs and all(ct[i] == length for i in range(max(-length, -len(ct)), 0))


def decrypt(ctext, bs, test):
    """
    Decrypts through padding oracle attack against CBC with PKCS7 padding.

    Args:
        ctext(bytes): The cipher text.
        bs(int): The block size.
        test(function): A function taking a ciphertext as argument and returning a boolean
            indicating whether the padding is valid after decrypting. This is the *oracle*.

    Returns:
        bytes: The plain text.

    Raises:
        ValueError: if the test function never finds a valid padding.
    """

    try:
        return co_plug(decryptor(ctext, bs), co_repeat(test))
    except ValueError:
        return co_plug(decryptor(ctext, bs, last_unchanged=True), co_repeat(test))
