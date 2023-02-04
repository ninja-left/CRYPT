# -*- coding: UTF-8 -*-

"""
    CRYPT, Encryption/Decryption Tool
    Copyright (C) 2022  N1nj4 R8

    CRYPT is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    CRYPT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with CRYPT.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import annotations
from os import sep
from pathlib import Path
import time
import base64
from string import ascii_letters
import hashlib
import passlib.hash as passlibHash

# Colors
grn = "\x1b[0;32m"  # Green
red = "\x1b[0;31m"  # Red
wte = "\x1b[0;37m"  # White
ppl = "\x1b[0;35m"  # Purple (Magenta)
ylo = "\x1b[0;36m"  # Yellow
blu = "\x1b[0;36m"  # Blue
cyn = "\x1b[0;36m"  # Cyan
gry = "\x1b[0;90m"  # Grey (Light Black)


enc_path = f".{sep}Results{sep}Encrypted.txt"
dec_path = f".{sep}Results{sep}Decrypted.txt"


def enc_writer(
    txt: str,
    cipher: str,
    method: str | dict[int, str],
    path: str = enc_path,
    cc: bool = False,
    cc_key: int | None = None,
    is_hash: bool = False,
):
    """
    Parameters:
    ---
        Required:
        ---
        - txt: The input text.
        - cipher: The cipher name; 'Base64', 'Morse Code', and ... .
        - method: The function that encrypts the text.
        * Example: Base64 --> base64_encrypt(bytes(txt, "utf-8"))

        Optional:
        ---
        - path: The path to write the file.
        - cc: checks if it's Caesar Cipher; Default is False.
        - cc_key: The key used to shift the text.
        - is_hash: True if it's a hash; Default is False.
    """
    deco = "#" * 50
    times = (
        f"\n At {time.localtime().tm_hour}:{time.localtime().tm_min}:{time.localtime().tm_sec}"
        f" {time.localtime().tm_mday}/{time.localtime().tm_mon}/{time.localtime().tm_year}"
    )

    enc_text = f"{deco}{times}\n\n Plain Text: {txt}\n\n Encrypted {cipher}: {method}\n\n{deco}\n"
    if cc:
        enc_text = f"{deco}{times}\n\n Plain Text: {txt}\n key: {cc_key}\n\n Encrypted {cipher}: {method}\n\n{deco}\n"
    if is_hash:
        enc_text = f"{deco}{times}\n\n Plain Text: {txt}\n\n {cipher} Hash: {method}\n\n{deco}\n"
    path_dir = path.split(sep)
    path_dir.pop(-1)
    save_dir = Path(sep.join(path_dir))
    if not save_dir.exists():
        save_dir.mkdir(parents=True)
    with open(path, "a+") as file:
        file.write(enc_text)


def dec_writer(
    txt: str,
    cipher: str,
    method: str | dict[int, str],
    path: str = dec_path,
    cc: bool = False,
    cc_key: int | None = None,
    is_hash: bool = False,
):
    """
    Parameters:
    ---
    - txt: The input text.
    - cipher: The cipher name; 'Base64', 'Caesar Cipher', and ...
    - method: The function that decrypts the text;
    * Example: Base64 -> base64_decrypt(bytes(txt, "utf-8"))

    Optional:
    - path: The path to write the file; If not set, default will be used.
    - cc: checks if it's Caesar Cipher; Default is False.
    - cc_key: The key used to shift the text.
    """
    deco = "#" * 50
    times = (
        f"\n At {time.localtime().tm_hour}:{time.localtime().tm_min}:{time.localtime().tm_sec}"
        f" {time.localtime().tm_mday}/{time.localtime().tm_mon}/{time.localtime().tm_year}"
    )

    dec_text = f"{deco}{times}\n\n Encrypted {cipher}: {txt}\n\n Decrypted Text: {method}\n\n{deco}\n"
    if cc:
        dec_text = f"{deco}{times}\n\n Encrypted {cipher}: {txt}\n Key: {cc_key}\n\n Decrypted Text: {method}\n\n{deco}\n"
    if is_hash:
        dec_text = f"{deco}{times}\n\n Hash: {txt}\n\n {cipher} Decrypted: {method}\n\n{deco}\n"
    path_dir = path.split(sep)
    path_dir = path_dir.pop(-1)
    save_dir = Path(path_dir.join(sep))
    if not save_dir.exists():
        save_dir.mkdir(parents=True)
    with open(path, "a+") as file:
        file.write(dec_text)


# Base16
def base16_encode(txt: str) -> str:
    return base64.b16encode(txt.encode("utf-8")).decode("utf-8")


def base16_decode(b16encoded: str) -> str:
    return base64.b16decode(b16encoded.encode("utf-8")).decode("utf-8")


# Base32
def base32_encode(string: str) -> str:
    return base64.b32encode(string.encode("utf-8")).decode("utf-8")


def base32_decode(encoded_bytes: str) -> str:
    return base64.b32decode(encoded_bytes.encode("utf-8")).decode("utf-8")


# Base85
def base85_encode(string: str) -> str:
    return base64.b85encode(string.encode("utf-8")).decode("utf-8")


def base85_decode(a85encoded: str) -> str:
    return base64.b85decode(a85encoded.encode("utf-8")).decode("utf-8")


# Base64
B64_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def base64_encrypt(text: str) -> str:
    """Encodes data according to RFC4648.
    The data is first transformed to binary and appended with binary digits so that its
    length becomes a multiple of 6, then each 6 binary digits will match a character in
    the B64_CHARSET string. The number of appended binary digits would later determine
    how many "=" signs should be added, the padding.
    For every 2 binary digits added, a "=" sign is added in the output.
    We can add any binary digits to make it a multiple of 6, for instance, consider the
    following example:
    "AA" -> 0010100100101001 -> 001010 010010 1001
    As can be seen above, 2 more binary digits should be added, so there's 4
    possibilities here: 00, 01, 10 or 11.
    That being said, Base64 encoding can be used in Steganography to hide data in these
    appended digits.
    """
    data = text.encode()
    binary_stream = "".join(bin(byte)[2:].zfill(8) for byte in data)

    padding_needed = len(binary_stream) % 6 != 0

    if padding_needed:
        # The padding that will be added later
        padding = b"=" * ((6 - len(binary_stream) % 6) // 2)

        # Append binary_stream with arbitrary binary digits (0's by default) to make its
        # length a multiple of 6.
        binary_stream += "0" * (6 - len(binary_stream) % 6)
    else:
        padding = b""

    # Encode every 6 binary digits to their corresponding Base64 character
    return (
        "".join(
            B64_CHARSET[int(binary_stream[index : index + 6], 2)]
            for index in range(0, len(binary_stream), 6)
        ).encode()
        + padding
    ).decode()


def base64_decrypt(encoded_data: str) -> str:
    """Decodes data according to RFC4648.
    This does the reverse operation of base64_encode.
    We first transform the encoded data back to a binary stream, take off the
    previously appended binary digits according to the padding, at this point we
    would have a binary stream whose length is multiple of 8, the last step is
    to convert every 8 bits to a byte.
    """

    # In case encoded_data is a bytes-like object, make sure it contains only
    # ASCII characters so we convert it to a string object
    if isinstance(encoded_data, bytes):
        try:
            encoded_data = encoded_data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("base64 encoded data should only contain ASCII characters")

    padding = encoded_data.count("=")

    if padding:  # Check if the encoded string contains non base64 characters
        assert all(
            char in B64_CHARSET for char in encoded_data[:-padding]
        ), "Invalid base64 character(s) found."
    else:
        assert all(
            char in B64_CHARSET for char in encoded_data
        ), "Invalid base64 character(s) found."

    # check padding
    assert len(encoded_data) % 4 == 0 and padding < 3, "Incorrect padding"
    if padding:  # Remove padding if there is one
        encoded_data = encoded_data[:-padding]
        binary_stream = "".join(
            bin(B64_CHARSET.index(char))[2:].zfill(6) for char in encoded_data
        )[: -padding * 2]
    else:
        binary_stream = "".join(
            bin(B64_CHARSET.index(char))[2:].zfill(6) for char in encoded_data
        )
    data = [
        int(binary_stream[index : index + 8], 2)
        for index in range(0, len(binary_stream), 8)
    ]
    return bytes(data).decode()


# Caesar Cipher
def cc_encrypt(input_string: str, key: int, alphabet: str | None = None) -> str:
    """
    Parameters:
    -----------
    *   input_string: the plain-text that needs to be encoded
    *   key: the number of letters to shift the message by

    Optional:
    *   alphabet (None): the alphabet used to encode the cipher, if not
        specified, the standard english alphabet with upper and lowercase
        letters is used
    * change [alphabet: None] to [alphabet: str]
    """

    # Set default alphabet to lower and upper case english chars
    alpha = alphabet or ascii_letters

    # The final result string
    result = ""

    for character in input_string:
        if character not in alpha:
            # Append without encryption if character is not in the alphabet
            result += character
        else:
            # Get the index of the new key and make sure it isn't too large
            new_key = (alpha.index(character) + key) % len(alpha)

            # Append the encoded character to the alphabet
            result += alpha[new_key]

    return result


def cc_decrypt(input_string: str, key: int, alphabet: str | None = None) -> str:
    """
    Parameters:
    -----------
    *   input_string: the cipher-text that needs to be decoded
    *   key: the number of letters to shift the message backwards by to decode

    Optional:
    *   alphabet (None): the alphabet used to decode the cipher, if not
        specified, the standard english alphabet with upper and lowercase
        letters is used
    """

    # Turn on decode mode by making the key negative
    key *= -1
    return cc_encrypt(input_string, key, alphabet)


def cc_brute_force(input_string: str, alphabet: str | None = None) -> dict[int, str]:
    """
    Parameters:
    -----------
    *   input_string: the cipher-text that needs to be used during brute-force

    Optional:
    *   alphabet:  (None): the alphabet used to decode the cipher, if not
        specified, the standard english alphabet with upper and lowercase
        letters is used
    """

    # Set default alphabet to lower and upper case english chars
    alpha = alphabet or ascii_letters

    # To store data on all the combinations
    brute_force_data = {}

    # Cycle through each combination
    for key in range(1, len(alpha) + 1):
        # Decrypt the message and store the result in the data
        brute_force_data[f"Key {key}"] = cc_decrypt(input_string, key, alpha)

    return brute_force_data


# Morse Code
MORSE_CODE_DICT = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    "0": "-----",
    "&": ".-...",
    "@": ".--.-.",
    ":": "---...",
    ",": "--..--",
    ".": ".-.-.-",
    "'": ".----.",
    '"': ".-..-.",
    "_": "..--.-",
    "$": "...-..-",
    "?": "..--..",
    "/": "-..-.",
    "=": "-...-",
    "+": ".-.-.",
    "-": "-....-",
    "(": "-.--.",
    ")": "-.--.-",
    "!": "-.-.--",
    " ": "/",
}  # Exclamation mark is not in ITU-R recommendation
REVERSE_DICT = {value: key for key, value in MORSE_CODE_DICT.items()}


def mc_encrypt(message: str) -> str:
    return " ".join(MORSE_CODE_DICT[char] for char in message.upper())


def mc_decrypt(message: str) -> str:
    return "".join(REVERSE_DICT[char] for char in message.split())


# Baconian Cipher
encode_dict = {
    "a": "AAAAA",
    "b": "AAAAB",
    "c": "AAABA",
    "d": "AAABB",
    "e": "AABAA",
    "f": "AABAB",
    "g": "AABBA",
    "h": "AABBB",
    "i": "ABAAA",
    "j": "BBBAA",
    "k": "ABAAB",
    "l": "ABABA",
    "m": "ABABB",
    "n": "ABBAA",
    "o": "ABBAB",
    "p": "ABBBA",
    "q": "ABBBB",
    "r": "BAAAA",
    "s": "BAAAB",
    "t": "BAABA",
    "u": "BAABB",
    "v": "BBBAB",
    "w": "BABAA",
    "x": "BABAB",
    "y": "BABBA",
    "z": "BABBB",
    " ": " ",
}
decode_dict = {value: key for key, value in encode_dict.items()}


def bacon_encode(word: str) -> str:
    encoded = ""
    for letter in word.lower():
        if letter.isalpha() or letter == " ":
            encoded += encode_dict[letter]
        else:
            raise Exception("encode() accepts only letters of the alphabet and spaces")
    return encoded


def bacon_decode(coded: str) -> str:
    if set(coded) - {"A", "B", " "} != set():
        raise Exception("decode() accepts only 'A', 'B' and spaces")
    decoded = ""
    for word in coded.split():
        while len(word) != 0:
            decoded += decode_dict[word[:5]]
            word = word[5:]
        decoded += " "
    return decoded.strip()


# Hashes
def md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def md5_crypt(text: str) -> str:
    return passlibHash.md5_crypt.hash(text)


def md5_salted(text: str) -> str:
    return passlibHash.ldap_salted_md5.hash(text)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def sha256_crypt(text: str) -> str:
    return passlibHash.sha256_crypt.hash(text)


def sha256_salted(text: str) -> str:
    return passlibHash.ldap_salted_sha256.hash(text)


def sha512(text: str) -> str:
    return hashlib.sha512(text.encode()).hexdigest()


def sha512_crypt(text: str) -> str:
    return passlibHash.sha512_crypt.hash(text)


def sha512_salted(text: str) -> str:
    return passlibHash.ldap_salted_sha512.hash(text)


def bcrypt(text: str) -> str:
    return passlibHash.bcrypt.hash(text)


def argon2(text: str) -> str:
    return passlibHash.argon2.hash(text)


def nthash(text: str) -> str:
    return passlibHash.nthash.hash(text)


def pbkdf2_256(text: str) -> str:
    return passlibHash.pbkdf2_sha256.hash(text)


def pbkdf2_512(text: str) -> str:
    return passlibHash.pbkdf2_sha512.hash(text)
