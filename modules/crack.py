# -*- coding: UTF-8 -*-
"""
    CRYPT Brute Forcer, Password Hash Brute Forcing Tool
    Copyright (C) 2022  N1nj4 R8

    CRYPT Brute Forcer is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    CRYPT Brute Forcer is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with CRYPT Brute Forcer.  If not, see <https://www.gnu.org/licenses/>.
"""


from passlib.context import CryptContext
from pathlib import Path
from brute import brute
from tqdm import tqdm
import modules.clear as clear
import time
import modules.main as main
from keyboard import wait
from os import sep
from modules.functions import md5, sha256, sha512

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
    path_dir = path_dir.pop(-1)
    save_dir = Path(path_dir)
    if not save_dir.exists():
        save_dir.mkdir(parents=True)
    encrypted_file = open(path, "a+")
    encrypted_file.write(enc_text)
    encrypted_file.close()


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
    save_dir = Path(path_dir)
    if not save_dir.exists():
        save_dir.mkdir(parents=True)
    decrypted_file = open(path, "a+")
    decrypted_file.write(dec_text)
    decrypted_file.close()


def crackHash_menu(file_write: bool):
    while True:
        clear.cl_all_v2()
        print(main.menu_crackers())
        cmd_cracker = input(f"{grn}        CRYPT>{wte} ")
        if cmd_cracker == "1":  # Brute Force
            clear.cl_all_v2()
            hash = input(f"\n{grn}        [+] Hash:{wte} ")
            length = int(input(f"\n{grn}        [+] Max Length:{wte} "))
            print(
                "\nIf 1, ramp up from start_length till length; Otherwise, iterate over current length values."
            )
            ramp = bool(int(input(f"{grn}        [+] Ramp? [1/0]:{wte} ")))
            start_length = int(input(f"\n{grn}        [+] Start length [0<=]:{wte} "))
            have_letters = bool(
                int(input(f"\n{grn}        [+] Include Letters? [1/0]:{wte} "))
            )
            have_symbols = bool(
                int(input(f"\n{grn}        [+] Include Symbols? [1/0]:{wte} "))
            )
            have_numbers = bool(
                int(input(f"\n{grn}        [+] Include Numbers? [1/0]:{wte} "))
            )
            hash_type = input(
                f"\n{grn}        [+] Hash Type [md5/sha256/sha512/auto]:{wte} "
            ).lower()
            if (
                not hash_type in ["md5", "sha256", "sha512"]
                or not 3 <= len(hash_type) <= 6
            ):
                hash_type = "auto"
            results = crackHash_BruteForce(
                hash=hash,
                length=length,
                ramp=ramp,
                start_length=start_length,
                have_letters=have_letters,
                have_symbols=have_symbols,
                have_numbers=have_numbers,
                hash_type=hash_type,
            )
            print(f"{ylo}\n\nResults:\n{wte}{results}")

            if file_write:
                path = f".{sep}Results{sep}Hash_BF.txt"
                dec_writer(
                    hash,
                    "Brute Forced",
                    results,
                    path,
                    is_hash=True,
                )
            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
            wait("enter")

        elif cmd_cracker == "2":  # Wordlist
            clear.cl_all_v2()
            hash = input(f"\n{grn}        [+] Hash:{wte} ")

        elif cmd_cracker.upper() == "B":
            break


def crackHash_BruteForce(
    hash: str,
    length: int,
    ramp: bool,
    start_length: int = 1,
    have_letters: bool = True,
    have_symbols: bool = True,
    have_numbers: bool = True,
    hash_type: str = "auto",
):
    """
    ----
    Parameters
    ----------
    * hash: Hash to crack.
    * length: Length of string to iterate through.
    * ramp: If true, ramp up from start_length till length; Otherwise, iterate over current length values.
    * have_letters: Include uppercase & lowercase letters; default: True.
    * have_symbols: Include symbols; default: True.
    * have_numbers: Include 0-9 digit; default: Trues.
    * start_length: The length of the string to begin ramping through; default: 1.
    * hash_type: Type of hash trying to crack.
    """
    bar = tqdm()
    results = "Match not found"
    ctx = CryptContext(
        [
            "md5_crypt",
            "ldap_salted_md5",
            "sha256_crypt",
            "ldap_salted_sha256",
            "sha512_crypt",
            "ldap_salted_sha512",
            "bcrypt",
            "argon2",
            "nthash",
            "pbkdf2_sha256",
            "pbkdf2_sha512",
        ]
    )
    for password in brute(
        start_length=start_length,
        length=length,
        letters=have_letters,
        symbols=have_symbols,
        numbers=have_numbers,
        ramp=ramp,
    ):
        bar.set_description_str(f"Testing {password}")
        if hash_type == "auto":
            check = ctx.verify(password, hash)
            if check:
                results = f"Match found: {password}"
                break
        elif hash_type == "md5":
            check = md5(password)
            if check == hash:
                results = f"Match found: {password}"
                break
        elif hash_type == "sha256":
            check = sha256(password)
            if check == hash:
                results = f"Match found: {password}"
                break
        elif hash_type == "sha512":
            check = sha512(password)
            if check == hash:
                results = f"Match found: {password}"
                break
        bar.update()
    bar.close()
    return results


def crackHash_WordList(hash: str, file_path: str | Path):
    results = ""
    file_obj = open(file_path, "r", encoding="UTF-8")
    bar = tqdm()
    for password in file_obj:
        bar.set_description(f"Testing {password}")
        if password == hash:
            print("Match found: ", password)
            bar.close()
            break
        bar.update()

    return results
