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

import os
from pprint import pprint
from modules import main, art, clear, functions
from modules.crack import *
import sys


# Colors
grn = "\x1b[0;32m"  # Green
red = "\x1b[0;31m"  # Red
wte = "\x1b[0;37m"  # White
ppl = "\x1b[0;35m"  # Purple (Magenta)
ylo = "\x1b[0;36m"  # Yellow
blu = "\x1b[0;36m"  # Blue
cyn = "\x1b[0;36m"  # Cyan
gry = "\x1b[0;90m"  # Grey (Light Black)


if __name__ == "__main__":
    write_to_file = False
    while True:
        try:
            clear.cl_all_v2()
            art.Crypt_Logo(red, gry, grn)
            print(main.menu(ylo, ppl, wte))

            cmd_main = input(f"{grn}        CRYPT> {wte}")

            if cmd_main == "1":  # Base16
                while True:
                    clear.cl_all_v2()
                    print(main.menu_base(16))
                    b16_cmd = input(f"{grn}        Crypt> {wte}")
                    try:
                        clear.cl_all_v2()
                        if b16_cmd.upper() == "E":
                            text_input = input(f"\n{grn}        [+] Text: {wte}")

                            results = functions.base16_encode(text_input)
                            print(f"{cyn}[+] Encrypted:\n{wte}{results}")

                            if write_to_file:
                                functions.enc_writer(text_input, "Base16", results)

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b16_cmd.upper() == "D":
                            text_input = input(f"{cyn}        [+] Encoded Text: {wte}")

                            results = functions.base16_decode(text_input)
                            print(f"{ylo}\n\nDecoded:\n{wte}{results}")

                            if write_to_file:
                                functions.dec_writer(text_input, "Base16", results)

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b16_cmd.upper() == "I":
                            print(main.info_b16)
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b16_cmd.upper() == "B":
                            break

                    except:
                        print(main.error_logo(red))
                        print(f"{red}\n\t[!!] Unexpected Error Happened!")
                        print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                        input()

            elif cmd_main == "2":  # Base32
                while True:
                    clear.cl_all_v2()
                    print(main.menu_base(32))
                    b32_cmd = input(f"{grn}        Crypt> {wte}")
                    try:
                        clear.cl_all_v2()
                        if b32_cmd.upper() == "E":
                            text_input = input(f"\n{grn}        [+] Text: {wte}")

                            results = functions.base32_encode(text_input)
                            print(f"{cyn}[+] Encoded:\n{wte}{results}")

                            if write_to_file:
                                functions.enc_writer(text_input, "Base32", results)

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b32_cmd.upper() == "D":
                            text_input = input(f"{cyn}        [+] Encoded Text: {wte}")

                            results = functions.base32_decode(text_input)
                            print(f"{ylo}\n\nDecoded:\n{wte}{results}")

                            if write_to_file:
                                functions.dec_writer(text_input, "Base32", results)

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b32_cmd.upper() == "I":
                            print(main.info_b32)
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b32_cmd.upper() == "B":
                            break

                    except:
                        print(main.error_logo(red))
                        print(f"{red}\n\t[!!] Unexpected Error Happened!")
                        print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                        input()

            elif cmd_main == "3":  # Base64
                while True:
                    clear.cl_all_v2()
                    print(main.menu_base(64))
                    b64_command = input(f"{grn}        Crypt> {wte}")
                    try:
                        clear.cl_all_v2()
                        if b64_command.upper() == "E":
                            b64_en = input(f"\n{grn}        [+] Text: {wte}")

                            results = functions.base64_encrypt(b64_en)
                            print(f"{cyn}[+] Encoded:\n{wte}{results}")

                            if write_to_file:
                                functions.enc_writer(b64_en, "Base64", results)

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b64_command.upper() == "D":
                            b64_de = input(f"{cyn}        [+] Encoded Text: {wte}")

                            results = functions.base64_decrypt(b64_de)
                            print(f"{ylo}\n\nDecoded:\n{wte}{results}")

                            if write_to_file:
                                functions.dec_writer(b64_de, "Base64", results)

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b64_command.upper() == "I":
                            print(main.info_b64)
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b64_command.upper() == "B":
                            break

                    except:
                        print(main.error_logo(red))
                        print(f"{red}\n\t[!!] Unexpected Error Happened!")
                        print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                        input()

            elif cmd_main == "4":  # Caesar Cipher
                while True:
                    clear.cl_all_v2()
                    print(main.menu_cc())
                    cc_command = input(f"{grn}        Crypt> {wte}")
                    try:
                        clear.cl_all_v2()
                        if cc_command.upper() == "E":
                            text_input = input(f"\n{grn}        [+] Text: {wte}")
                            print(
                                f'{ylo}\n\n[!] "Key" is the number of letters to shift the message by.'
                            )
                            cc_key = int(input(f"{grn}        [+] Key: {wte}"))

                            results = functions.cc_encrypt(text_input, cc_key)
                            print(f"\n\n{cyn}[+] Encrypted: \n{wte}{results}")

                            if write_to_file:
                                functions.enc_writer(
                                    text_input,
                                    "Caesar Cipher",
                                    results,
                                    cc=True,
                                    cc_key=cc_key,
                                )

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cc_command.upper() == "D":
                            text_input = input(
                                f"\n{grn}        [+] Encrypted Text: {wte}"
                            )
                            print(
                                f'{ylo}\n\n[!] "key" is the number of letters to shift the message backward by.'
                            )
                            cc_key = int(input(f"{grn}        [+] Key: {wte}"))

                            results = functions.cc_decrypt(text_input, cc_key)

                            print(f"\n\n{cyn}[+] Decrypted: \n{wte}{results}")

                            if write_to_file:
                                functions.dec_writer(
                                    text_input,
                                    "Caesar Cipher",
                                    results,
                                    cc=True,
                                    cc_key=cc_key,
                                )

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cc_command.upper() == "F":
                            print(main.info_cc_bf)
                            text_input = input(
                                f"\n{grn}        [+] Encrypted Text: {wte}"
                            )

                            results = functions.cc_brute_force(text_input)
                            brute_path = f".{os.sep}Results{os.sep}CC_BruteForce.txt"
                            print(f"\n\n{cyn}[+] Decrypted Texts: \n{wte}")
                            pprint(results, sort_dicts=False)

                            if write_to_file:
                                functions.dec_writer(
                                    text_input,
                                    "Caesar Cipher Brute-Force",
                                    results,
                                    brute_path,
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cc_command.upper() == "I":
                            print(main.info_cc)
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cc_command.upper() == "B":
                            break

                    except:
                        print(main.error_logo(red))
                        print(f"{red}\n\t[!!] Unexpected Error Happened!")
                        print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                        input()

            elif cmd_main == "5":  # Morse Code
                while True:
                    clear.cl_all_v2()
                    print(main.menu_morse())
                    mc_command = input(f"{grn}        Crypt> {wte}")
                    try:
                        clear.cl_all_v2()
                        if mc_command.upper() == "E":
                            text_input = input(f"{grn}\n        [+] Text: {wte}")

                            results = functions.mc_encrypt(text_input)
                            print(f"\n\n{cyn}[+] Encrypted:\n{wte}{results}")

                            if write_to_file:
                                functions.enc_writer(text_input, "Morse Code", results)

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif mc_command.upper() == "D":
                            text_input = input(
                                f"{grn}\n        [+] Encrypted Text: {wte}"
                            )

                            results = functions.mc_decrypt(text_input)
                            print(f"\n\n{cyn}[+] Decrypted:\n{wte}{results}")

                            if write_to_file:
                                functions.dec_writer(text_input, "Morse Code", results)

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif mc_command.upper() == "I":
                            print(main.info_mc)
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif mc_command.upper() == "B":
                            break

                    except:
                        print(main.error_logo(red))
                        print(f"{red}\n\t[!!] Unexpected Error Happened!")
                        print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                        input()

            elif cmd_main == "6":  # Base85
                while True:
                    clear.cl_all_v2()
                    print(main.menu_base(85))
                    b85_command = input(f"{grn}        Crypt> {wte}")
                    try:
                        clear.cl_all_v2()
                        if b85_command.upper() == "E":
                            text_input = input(f"\n{grn}        [+] Text: {wte}")

                            results = functions.base85_encode(text_input)
                            print(f"{cyn}[+] Encrypted:\n{wte}{results}")

                            if write_to_file:
                                functions.enc_writer(text_input, "Base85", results)

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b85_command.upper() == "D":
                            b85_de = input(f"{cyn}[+]        Encrypted Text: {wte}")

                            results = functions.base85_decode(b85_de)
                            print(f"{ylo}\n\nDecrypted:\n{wte}{results}")

                            if write_to_file:
                                functions.dec_writer(b85_de, "Base85", results)

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b85_command.upper() == "I":
                            print(main.info_b85)
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif b85_command.upper() == "B":
                            break

                    except:
                        print(main.error_logo(red))
                        print(f"{red}\n\t[!!] Unexpected Error Happened!")
                        print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                        input()

            elif cmd_main == "7":  # Baconian Cipher
                while True:
                    clear.cl_all_v2()
                    print(main.menu_bacon())
                    bacon_cmd = input(f"{grn}        Crypt> {wte}")
                    try:
                        clear.cl_all_v2()
                        if bacon_cmd.upper() == "E":
                            bacon_txt = input(f"\n{grn}        [+] Text: {wte}")

                            results = functions.bacon_encode(bacon_txt)
                            print(f"{cyn}[+] Encrypted:\n{wte}{results}")

                            if write_to_file:
                                functions.enc_writer(
                                    bacon_txt, "Baconian Cipher", results
                                )

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif bacon_cmd.upper() == "D":
                            bacon_dec = input(f"{cyn}[+] Encrypted Text: {wte}")

                            results = functions.bacon_decode(bacon_dec)
                            print(f"{ylo}\n\nDecrypted:\n{wte}{results}")

                            if write_to_file:
                                functions.dec_writer(
                                    bacon_dec, "Baconian Cipher", results
                                )

                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif bacon_cmd.upper() == "I":
                            print(main.info_bc)
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif bacon_cmd == "B":
                            break

                    except:
                        print(main.error_logo(red))
                        print(f"{red}\n\t[!!] Unexpected Error Happened!")
                        print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                        input()

            elif cmd_main == "8":  # MD5
                while True:
                    clear.cl_all_v2()
                    print(main.menu_hash("MD5"))
                    cmd_hash = input(f"{grn}        CRYPT> {wte}")
                    if cmd_hash == "1":
                        text_input = input(f"\n{grn}        [+] Text: {wte}")

                        results = functions.md5(text_input)
                        path = f".{os.sep}Results{os.sep}Hash_MD5.txt"
                        print(f"{cyn}[+] Generated:\n{wte}{results}")

                        if write_to_file:
                            functions.enc_writer(
                                text_input, "MD5 Hash", results, path, is_hash=True
                            )

                        print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                        input()

                    elif cmd_hash == "2":
                        crackHash_menu(write_to_file)

                    elif cmd_hash.upper() == "B":
                        break

            elif cmd_main == "9":  # More
                while True:
                    try:
                        clear.cl_all_v2()
                        art.Crypt_Logo(red, gry, grn)
                        print(main.menu_more(ylo, ppl, wte))

                        cmd_more = input(f"{grn}        CRYPT> {wte}")

                        if cmd_more == "1":  # Md5 Crypt
                            clear.cl_all_v2()
                            print(f"{wte}\n MD5 Crypt")
                            text_input = input(f"\n{grn}        [+] Text:{wte} ")

                            results = functions.md5_crypt(text_input)
                            path = f".{os.sep}Results{os.sep}Hash_MD5.txt"
                            print(f"{cyn}[+] Generated:\n{wte}{results}")
                            if write_to_file:
                                functions.enc_writer(
                                    text_input,
                                    "MD5 Crypt",
                                    results,
                                    path,
                                    is_hash=True,
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more == "2":  # Salted MD5
                            clear.cl_all_v2()
                            print(f"{wte}\n Salted MD5")
                            text_input = input(f"\n{grn}        [+] Text:{wte} ")

                            results = functions.md5_salted(text_input)
                            path = f".{os.sep}Results{os.sep}Hash_MD5.txt"
                            print(f"{cyn}[+] Generated:\n{wte}{results}")
                            if write_to_file:
                                functions.enc_writer(
                                    text_input,
                                    "MD5 Salted Hash",
                                    results,
                                    path,
                                    is_hash=True,
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more == "3":  # SHA256
                            while True:
                                clear.cl_all_v2()
                                print(main.menu_hash("SHA256"))
                                cmd_hash = input(f"{grn}        CRYPT> {wte}")
                                if cmd_hash == "1":
                                    text_input = input(
                                        f"\n{grn}        [+] Text: {wte}"
                                    )

                                    results = functions.sha256(text_input)
                                    path = f".{os.sep}Results{os.sep}Hash_SHA256.txt"
                                    print(f"{cyn}[+] Generated:\n{wte}{results}")
                                    if write_to_file:
                                        functions.enc_writer(
                                            text_input,
                                            "SHA256 Hash",
                                            results,
                                            path,
                                            is_hash=True,
                                        )

                                    print(
                                        f"{gry}\n\n\t[!] {wte}Press ENTER to continue..."
                                    )
                                    input()

                                elif cmd_hash == "2":
                                    crackHash_menu(write_to_file)

                                elif cmd_hash.upper() == "B":
                                    break

                        elif cmd_more == "4":  # SHA256 Crypt
                            clear.cl_all_v2()
                            print(f"{wte}\n SHA256 Crypt")
                            text_input = input(f"\n{grn}        [+] Text:{wte} ")

                            results = functions.sha256_crypt(text_input)
                            path = f".{os.sep}Results{os.sep}Hash_SHA256.txt"
                            print(f"{cyn}[+] Generated:\n{wte}{results}")
                            if write_to_file:
                                functions.enc_writer(
                                    text_input,
                                    "SHA256 Crypt",
                                    results,
                                    path,
                                    is_hash=True,
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more == "5":  # Salted SHA256
                            clear.cl_all_v2()
                            print(f"{wte}\n Salted SHA256")
                            text_input = input(f"\n{grn}        [+] Text:{wte} ")

                            results = functions.sha256_salted(text_input)
                            path = f".{os.sep}Results{os.sep}Hash_SHA256.txt"
                            print(f"{cyn}[+] Generated:\n{wte}{results}")
                            if write_to_file:
                                functions.enc_writer(
                                    text_input,
                                    "SHA256 Salted Hash",
                                    results,
                                    path,
                                    is_hash=True,
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more == "6":  # SHA512
                            while True:
                                clear.cl_all_v2()
                                print(main.menu_hash("SHA512"))
                                cmd_hash = input(f"{grn}        CRYPT> {wte}")
                                if cmd_hash == "1":
                                    text_input = input(
                                        f"\n{grn}        [+] Text: {wte}"
                                    )

                                    results = functions.sha512(text_input)
                                    path = f".{os.sep}Results{os.sep}Hash_SHA512.txt"
                                    print(f"{cyn}[+] Generated:\n{wte}{results}")
                                    if write_to_file:
                                        functions.enc_writer(
                                            text_input,
                                            "SHA512 Hash",
                                            results,
                                            path,
                                            is_hash=True,
                                        )

                                    print(
                                        f"{gry}\n\n\t[!] {wte}Press ENTER to continue..."
                                    )
                                    input()

                                elif cmd_hash == "2":
                                    crackHash_menu(write_to_file)

                                elif cmd_hash.upper() == "B":
                                    break

                        elif cmd_more == "7":  # SHA512 Crypt
                            clear.cl_all_v2()
                            print(f"{wte}\n SHA512 Crypt")
                            text_input = input(f"\n{grn}        [+] Text:{wte} ")

                            results = functions.sha512_crypt(text_input)
                            path = f".{os.sep}Results{os.sep}Hash_SHA512.txt"
                            print(f"{cyn}[+] Generated:\n{wte}{results}")
                            if write_to_file:
                                functions.enc_writer(
                                    text_input,
                                    "SHA512 Hash",
                                    results,
                                    path,
                                    is_hash=True,
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more == "8":  # Salted SHA512
                            clear.cl_all_v2()
                            print(f"{wte}\n SHA512")
                            text_input = input(f"\n{grn}        [+] Text:{wte} ")

                            results = functions.sha512_salted(text_input)
                            path = f".{os.sep}Results{os.sep}Hash_SHA512.txt"
                            print(f"{cyn}[+] Generated:\n{wte}{results}")
                            if write_to_file:
                                functions.enc_writer(
                                    text_input,
                                    "SHA512 Salted Hash",
                                    results,
                                    path,
                                    is_hash=True,
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more == "9":  # NT Hash
                            clear.cl_all_v2()
                            print(f"{wte}\n NT Hash")
                            text_input = input(f"\n{grn}        [+] Text:{wte} ")

                            results = functions.nthash(text_input)
                            path = f".{os.sep}Results{os.sep}Hash_NT.txt"
                            print(f"{cyn}[+] Generated:\n{wte}{results}")
                            if write_to_file:
                                functions.enc_writer(
                                    text_input, "NT Hash", results, path, is_hash=True
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more == "10":  # BCrypt
                            clear.cl_all_v2()
                            print(f"{wte}\n BCrypt")
                            text_input = input(f"\n{grn}        [+] Text:{wte} ")

                            results = functions.bcrypt(text_input)
                            path = f".{os.sep}Results{os.sep}Hash_Bcrypt.txt"
                            print(f"{cyn}[+] Generated:\n{wte}{results}")
                            if write_to_file:
                                functions.enc_writer(
                                    text_input, "BCrypt", results, path, is_hash=True
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more == "11":  # Argon2
                            clear.cl_all_v2()
                            print(f"{wte}\n Argon2")
                            text_input = input(f"\n{grn}        [+] Text:{wte} ")

                            results = functions.argon2(text_input)
                            path = f".{os.sep}Results{os.sep}Hash_Argon2.txt"
                            print(f"{cyn}[+] Generated:\n{wte}{results}")
                            if write_to_file:
                                functions.enc_writer(
                                    text_input, "Argon2", results, path, is_hash=True
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more == "12":  # PBKDF2-SHA256
                            clear.cl_all_v2()
                            print(f"{wte}\n PBKDF2-SHA256")
                            text_input = input(f"\n{grn}        [+] Text:{wte} ")

                            results = functions.pbkdf2_256(text_input)
                            path = f".{os.sep}Results{os.sep}Hash_PBKDF2.txt"
                            print(f"{cyn}[+] Generated:\n{wte}{results}")
                            if write_to_file:
                                functions.enc_writer(
                                    text_input,
                                    "PBKDF2-SHA256",
                                    results,
                                    path,
                                    is_hash=True,
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more == "13":  # PBKDF2-SHA512
                            clear.cl_all_v2()
                            print(f"{wte}\n PBKDF2-SHA256")
                            text_input = input(f"\n{grn}        [+] Text:{wte} ")

                            results = functions.pbkdf2_512(text_input)
                            path = f".{os.sep}Results{os.sep}Hash_PBKDF2.txt"
                            print(f"{cyn}[+] Generated:\n{wte}{results}")
                            if write_to_file:
                                functions.enc_writer(
                                    text_input,
                                    "PBKDF2-SHA512",
                                    results,
                                    path,
                                    is_hash=True,
                                )
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more == "14":  # Hash Crackers
                            crackHash_menu(write_to_file)

                        elif cmd_more.upper() == "B":
                            break

                        elif cmd_more.upper() == "A":
                            clear.cl_all_v2()
                            art.about(ylo, wte, grn, cyn)
                            print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                            input()

                        elif cmd_more.upper() == "F":
                            file_write = input(
                                f"{gry}\n\t Current> {write_to_file}{grn}\n\t[?] Write results to file?[y/N]{wte} "
                            )
                            if file_write.lower() == "y":
                                write_to_file = True
                            else:
                                write_to_file = False

                    except KeyboardInterrupt:
                        continue

            elif cmd_main.upper() == "A":
                clear.cl_all_v2()
                art.about(ylo, wte, grn, cyn)
                print(f"{gry}\n\n\t[!] {wte}Press ENTER to continue...")
                input()

            elif cmd_main.upper() == "F":
                file_write = input(
                    f"{gry}\n\t Current> {write_to_file}{grn}\n\t[?] Write results to file?[y/N]{wte} "
                )
                if file_write.lower() == "y":
                    write_to_file = True
                else:
                    write_to_file = False

            elif cmd_main.upper() == "E":
                sys.exit(0)

        except KeyboardInterrupt:
            continue

        except SystemExit:
            raise

        except:
            print(main.error_logo(red))
            print(f"{red}\n\t[!!] Unexpected Error Occurred!")
            error_choice = input(f"\n{ylo} Show error message?[y/N]:{wte} ").lower()
            if error_choice == "y":
                print(f"\n{ylo}[!] Error Message:{wte}")
                raise
            else:
                continue
