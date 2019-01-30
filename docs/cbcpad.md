Module cbcpad
=============
Padding oracle attack on CBC with PKCS7 padding

Functions
---------

`decrypt(ctext, bs, test)`
:   Decrypts through padding oracle attack against CBC with PKCS7 padding.
    
    Args:
        ctext(bytes): The cipher text.
        bs(int): The block size.
        test(function): A function taking a ciphertext as argument and returning a boolean
            indicating weather the padding is valid after decrypting. This is the *oracle*.
    
    Returns:
        bytes: The plain text.
    
    Raises:
        ValueError: if the test function never finds a valid padding.
