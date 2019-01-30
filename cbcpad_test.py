# This file is licensed under the terms of the MIT license.
# See the LICENSE file in the root of this repository for complete details.
import os
from hypothesis import given, settings, strategies as st

import cbcpad


def make_ptext(pad_size, bs):
    from cryptography.hazmat.primitives import padding

    text = b'A' * (3*bs - pad_size)
    padder = padding.PKCS7(bs*8).padder()
    return padder.update(text) + padder.finalize()


def make_cipher(key_size, bs):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    key = os.urandom(key_size)
    iv = os.urandom(bs)
    backend = default_backend()
    return Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)


def make_ctext(cipher, ptext):
    encryptor = cipher.encryptor()
    return encryptor.update(ptext) + encryptor.finalize()


def unpad(ptext, bs):
    from cryptography.hazmat.primitives import padding

    unpadder = padding.PKCS7(bs*8).unpadder()
    return unpadder.update(ptext) + unpadder.finalize()


def decrypt(cipher, ctext):
    decryptor = cipher.decryptor()
    return decryptor.update(ctext) + decryptor.finalize()


@settings(deadline=None)
@given(pad_size=st.integers(0, 15),
       key_size=st.just(16),
       bs=st.just(16))
def test_decrypt(pad_size, key_size, bs):
    def is_valid(ct):
        pt = decrypt(cipher, ct)
        try:
            unpad(pt, bs)
        except ValueError:
            return False
        return True

    cipher = make_cipher(key_size, bs)
    ptext1 = make_ptext(pad_size, bs)
    ctext = make_ctext(cipher, ptext1)
    ptext2 = cbcpad.decrypt(ctext, bs, is_valid)
    assert ptext1[bs:] == ptext2
