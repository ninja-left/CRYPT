#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
    CRYPT Bulk, Bulk Encryption/Decryption Tool
    Copyright (C) 2022  Ninja Left

    CRYPT Bulk is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    CRYPT Bulk is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with CRYPT Bulk.  If not, see <https://www.gnu.org/licenses/>.
"""

from io import TextIOWrapper
from os import get_terminal_size as term_size
import click
from modules import functions

# Colors
grn = "\x1b[0;32m"  # Green
red = "\x1b[0;31m"  # Red
rst = "\x1b[0m"  # Reset


def changer(plain: str, method: str, key: int | None = None) -> str:
    text = "Failed"
    if method == "md5":
        text = functions.md5(plain)

    elif method == "md5-salted":
        text = functions.md5_salted(plain)
    elif method == "sha256":
        text = functions.sha256(plain)
    elif method == "sha256-salted":
        text = functions.sha256_salted(plain)
    elif method == "sha512":
        text = functions.sha512(plain)
    elif method == "sha512-salted":
        text = functions.sha512_salted(plain)
    elif method == "nt-hash":
        text = functions.nthash(plain)
    elif method == "bcrypt":
        text = functions.bcrypt(plain)
    elif method == "pbkdf2-256":
        text = functions.pbkdf2_256(plain)
    elif method == "pbkdf2-512":
        text = functions.pbkdf2_512(plain)
    elif method == "argon2":
        text = functions.argon2(plain)
    elif method == "base16-e":
        text = functions.base16_encode(plain)
    elif method == "base32-e":
        text = functions.base32_encode(plain)
    elif method == "base64-e":
        text = functions.base64_encode(plain)
    elif method == "base85-e":
        text = functions.base85_encode(plain)
    elif method == "base16-d":
        text = functions.base16_decode(plain)
    elif method == "base32-d":
        text = functions.base32_decode(plain)
    elif method == "base64-d":
        text = functions.base64_decode(plain)
    elif method == "base85-d":
        text = functions.base85_decode(plain)
    elif method == "caesar-cipher":
        text = (
            functions.cc_cipher(plain, key) if isinstance(key, int) else "Invalid key"
        )
    elif method == "morse-code-e":
        text = functions.mc_encrypt(plain)
    elif method == "morse-code-d":
        text = functions.mc_decrypt(plain)
    elif method == "baconian-e":
        text = functions.bacon_encode(plain)
    elif method == "baconian-d":
        text = functions.bacon_decode(plain)

    return text


@click.command()
@click.option(
    "--file",
    "-F",
    "file",
    type=click.File(mode="r", encoding="UTF-8"),
    prompt=True,
    help="File containing plain text for encryption.",
)
@click.option(
    "--out",
    "-O",
    "output",
    type=click.Path(exists=False),
    prompt=True,
    help="Path/File to write the encrypted text to.",
)
@click.option(
    "--method",
    "-M",
    "method",
    type=click.Choice(
        [
            "md5",
            "md5-brute",
            "md5-salted",
            "sha256",
            "sha256-salted",
            "sha512",
            "sha512-salted",
            "nt-hash",
            "bcrypt",
            "pbkdf2-256",
            "pbkdf2-512",
            "argon2",
            "base16-d",
            "base32-d",
            "base64-d",
            "base85-d",
            "base16-e",
            "base32-e",
            "base64-e",
            "base85-e",
            "caesar-cipher",
            "morse-code-e",
            "morse-code-d",
            "baconian-e",
            "baconian-d",
        ],
        case_sensitive=False,
    ),
    prompt=True,
    help="Method to use for encryption.",
)
@click.option(
    "--key",
    "-K",
    "key",
    type=click.INT,
    default=0,
    help="Caesar Cipher encryption/decryption key. Positive integer for encryption, Negative integer for decryption.",
)
@click.option(
    "--about",
    "--copyright",
    "about",
    flag_value=True,
    default=False,
    help="Show About & Copyright",
)
def main(file: TextIOWrapper, output, method: str, about: bool, key: int) -> None:
    if about:
        print(
            f"""
        CRYPT, Encryption/Decryption Tool.
        Copyright (C) 2022  N1nj4 R8
    CRYPT comes with ABSOLUTELY NO WARRANTY.
    This is free software, and you are welcome to
    redistribute it under certain conditions; see
    LICENSE for details.
    """
        )
    try:
        with open(output, "w") as output:
            for line in file:
                line = line.strip()
                if method == "caesar-cipher":
                    text = changer(line, method, key=key)
                else:
                    text = changer(line, method)
                output.write(text)
                output.write("\n")

        print(grn, "─DONE─".center(term_size().columns, "═"), rst)
    except:
        print(red, "─ERROR─".center(term_size().columns, "═"), rst)
        raise


if __name__ == "__main__":
    main()
