# mc2pw/cbcpad

[![Build Status](https://travis-ci.org/mc2pw/cbcpad.svg?branch=master)](https://travis-ci.org/mc2pw/cbcpad)

Module `cbcpad` is an implementation of the padding oracle attack against CBC with
PKCS7 padding as described in the [wikipedia page](https://en.wikipedia.org/wiki/Padding_oracle_attack).

## Install

```sh
pip3 install git+https://gitlab.com/mc2pw/cbcpad.git
```

## Usage

If `ctext` is the cipher text and test is a oracle function, i.e. a function taking a
cipher text and returning a boolean based on whether the decrypted plain text has
valid padding, then we can run:

```python
>>> import cbcpad
>>> bs = 16 # block size
>>> cbcpad.decrypt(ctext, bs, test)
```

This will decrypt ctext minus the first block if it was encrypted using CBC with PKCS7
padding. One may need to try different block sizes (8, 16, 32, etc.).

## [Documentation](docs/cbcpad.md)

## License

MIT licensed. See the LICENSE file for details.

