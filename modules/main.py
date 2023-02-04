# -*- coding: UTF-8 -*-

from colorama import Fore

# Colors
grn = Fore.GREEN
red = Fore.RED
wte = Fore.WHITE
ppl = Fore.MAGENTA
ylo = Fore.YELLOW
blu = Fore.BLUE
cyn = Fore.CYAN
gry = Fore.LIGHTBLACK_EX

info_b16 = f"""{gry}
            Base16
        ==============
        Base16 can also refer to a binary to text encoding belonging
    to the same family as Base32, Base58, and Base64.
    In this case, data is broken into 4-bit sequences, and each value
    (between 0 and 15 inclusively) is encoded using one of 16 symbols
    from the ASCII character set. Although any 16 symbols from the ASCII
    character set can be used, in practice the ASCII digits '0'–'9' and
    the letters 'A'–'F' (or the lowercase 'a'–'f') are always chosen in
    order to align with standard written notation for hexadecimal numbers.
    
        More info: https://en.wikipedia.org/wiki/Hexadecimal#Base16_(transfer_encoding)
    """

info_b32 = f"""{gry}
            Base32
        ==============
        Base32 is a notation for encoding arbitrary byte data using
    a restricted set of symbols that can be conveniently used by
    humans and processed by computers.
    Base32 consists of a symbol set made up of 32 different characters,
    as well as an algorithm for encoding arbitrary sequences of 8-bit
    bytes into the Base32 alphabet. Because more than one 5-bit Base32
    symbol is needed to represent each 8-bit input byte, it also
    specifies requirements on the allowed lengths of Base32 strings
    (which must be multiples of 40 bits). The closely related Base64
    system, in contrast, uses a set of 64 symbols.

        More info: https://en.wikipedia.org/wiki/Base32
    """

info_b64 = f"""{gry}
            Base64
        ==============
        Base64 is a group of binary-to-text encoding schemes that
    represent binary data (more specifically, a sequence of 8-
    bit bytes) in sequences of 24 bits that can be represented
    by four 6-bit Base64 digits.
        Common to all binary-to-text encoding schemes, Base64 is designed
    to carry data stored in binary formats across channels that only
    reliably support text content. Base64 is particularly prevalent
    on the World Wide Web where one of its uses is the ability to
    embed image files or other binary assets inside textual assets
    such as HTML and CSS files.
        Base64 is also widely used for sending e-mail attachments. This
    is required because SMTP – in its original form – was designed
    to transport 7-bit ASCII characters only. This encoding causes
    an overhead of 33–37% (33% by the encoding itself; up to 4% more
    by the inserted line breaks).
        More info: https://en.wikipedia.org/wiki/Base64
    """

info_cc = f"""{gry}
          Caesar Cipher
        =================
        The caesar cipher is named after Julius Caesar who used it when sending
    secret military messages to his troops. This is a simple substitution cipher
    where very character in the plain-text is shifted by a certain number known
    as the "key" or "shift".

        Example:
    Say we have the following message: "Hello, captain"

    And our alphabet is made up of lower and uppercase letters: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    And our shift is "2"...

    We can then encode the message, one letter at a time. "H" would become "J",
    since "J" is two letters away, and so on. If the shift is ever two large, or
    our letter is at the end of the alphabet, we just start at the beginning
    ("Z" would shift to "a" then "b" and so on).
    Our final message would be "Jgnnq, ecrvckp"

        More info: https://en.m.wikipedia.org/wiki/Caesar_cipher

"""

info_cc_bf = f"""{gry}
            Brute Force
        =====================
        Brute force is when a person intercepts a message or password, not knowing
    the key and tries every single combination. This is easy with the caesar
    cipher since there are only all the letters in the alphabet. The more
    complex the cipher, the larger amount of time it will take to do brute force
    
        Example:
    Say we have a 5 letter alphabet (abcde), for simplicity and we intercepted the
    following message:
    "dbc"
    we could then just write out every combination:
    ecd... and so on, until we reach a combination that makes sense:
    "cab"
    
        More info: https://en.wikipedia.org/wiki/Brute-force_attack

"""

info_mc = f"""{gry}
            More Code
        =================
        Morse code is a method used in telecommunication to encode
    text characters as standardized sequences of two different signal
    durations, called dots and dashes, or dits and dahs. Morse code is
    named after Samuel Morse, one of the inventors of the telegraph.

    More info: https://en.wikipedia.org/wiki/Morse_code
"""

info_b85 = f"""{gry}
          Ascii85 (Base85)
        ====================
        Ascii85, also called Base85, is a form of binary-to-text
    encoding developed by Paul E. Rutter for the btoa utility.
    by using five ASCII characters to represent four bytes of
    binary data (making the encoded size 1⁄4 larger than the
    original, assuming eight bits per ASCII character), it is
    more efficient than uuencode or Base64, which use four
    characters to represent three bytes of data (1⁄3 increase,
    assuming eight bits per ASCII character).

    More info: https://en.wikipedia.org/wiki/Base85
    """

info_bc = f"""{gry}
          Baconian Cipher
        ===================
        Bacon's cipher or the Baconian cipher is a method of
    steganographic message encoding devised by Francis Bacon
    in 1605. A message is concealed in the presentation of
    text, rather than its content.
        To encode a message, each letter of the plaintext is
    replaced by a group of five of the letters 'A' or 'B'.
    This replacement is a 5-bit binary encoding and is done
    according to the alphabet of the Baconian cipher
    
        More info: https://en.wikipedia.org/wiki/Bacon%27s_cipher
"""


def menu(c1: str, c2: str, c3: str):
    """
    ---
    c1: Border lines.
    c2: Numbers.
    c3: Menus' text.
    """
    return f"""
{c1}        ╔══════════════════════╗
{c1}        ║ {c2}[1] {c3}Base16           {c1}║
{c1}        ║ {c2}[2] {c3}Base32           {c1}║
{c1}        ║ {c2}[3] {c3}Base64           {c1}║
{c1}        ║ {c2}[4] {c3}Caesar Cipher    {c1}║
{c1}        ║ {c2}[5] {c3}Morse Code       {c1}║
{c1}        ║ {c2}[6] {c3}Base85           {c1}║
{c1}        ║ {c2}[7] {c3}Baconian Cipher  {c1}║
{c1}        ║ {c2}[8] {c3}MD5              {c1}║
{c1}        ║ {c2}[9] {c3}More             {c1}║
{c1}        ╠══════════════════════╣
{c1}        ║ {cyn}[A] About            {c1}║
{c1}        ║ {ylo}[F] Log results      {c1}║
{c1}        ║ {red}[E] Exit             {c1}║
{c1}        ╚══════════════════════╝

    """


def menu_more(c1: str, c2: str, c3: str):
    """
    ---
    * c1: Border.
    * c2: Numbers.
    * c3: Menu text.
    """
    return f"""
{c1}        ╔══════════════════════╗
{c1}        ║ {c2}[01] {c3}MD5 Crypt       {c1}║
{c1}        ║ {c2}[02] {c3}Salted MD5      {c1}║
{c1}        ║ {c2}[03] {c3}SHA256          {c1}║
{c1}        ║ {c2}[04] {c3}SHA256 Crypt    {c1}║
{c1}        ║ {c2}[05] {c3}Salted SHA256   {c1}║
{c1}        ║ {c2}[06] {c3}SHA512          {c1}║
{c1}        ║ {c2}[07] {c3}SHA512 Crypt    {c1}║
{c1}        ║ {c2}[08] {c3}Salted SHA512   {c1}║
{c1}        ║ {c2}[09] {c3}NT Hash         {c1}║
{c1}        ║ {c2}[10] {c3}BCrypt          {c1}║
{c1}        ║ {c2}[11] {c3}Argon2          {c1}║
{c1}        ║ {c2}[12] {c3}PBKDF2+SHA256   {c1}║
{c1}        ║ {c2}[13] {c3}PBKDF2+SHA512   {c1}║
{c1}        ║ {c2}[14] {c3}Hash Crackers   {c1}║
{c1}        ╠══════════════════════╣
{c1}        ║ {cyn}[A] About            {c1}║
{c1}        ║ {ylo}[F] Log results      {c1}║
{c1}        ║ {red}[B] Back             {c1}║
{c1}        ╚══════════════════════╝

    """


def menu_crackers():
    return f"""
        Hash Crackers
{ylo}        ╔════════════════════╗
{ylo}        ║ {ppl}[1] {grn}Brute Force    {ylo}║
{ylo}        ║ {ppl}[2] {grn}WordList       {ylo}║
{ylo}        ╠════════════════════╣
{ylo}        ║ {red}[B] Back           {ylo}║
{ylo}        ╚════════════════════╝

    """


def menu_hash(hash_type: str):
    return f"""
        {hash_type}
{ylo}        ╔════════════════════╗
{ylo}        ║ {ppl}[1] {grn}Generate Hash    {ylo}║
{ylo}        ║ {ppl}[2] {grn}Crack Hash       {ylo}║
{ylo}        ╠════════════════════╣
{ylo}        ║ {red}[B] Back           {ylo}║
{ylo}        ╚════════════════════╝
    """


def menu_base(num: int):
    """
    Base{num} menu
    """
    return f"""
           Base {num}
{ylo}        ╔════════════════════╗
{ylo}        ║ {ppl}[E] {grn}Encrypt        {ylo}║
{ylo}        ║ {ppl}[D] {cyn}Decrypt        {ylo}║
{ylo}        ╠════════════════════╣
{ylo}        ║ {gry}[I] INFO.          {ylo}║
{ylo}        ║ {red}[B] Back           {ylo}║
{ylo}        ╚════════════════════╝

    """


def menu_cc():
    """
    Caesar Cipher menu
    """
    return f"""
        Caesar Cipher
{ylo}        ╔════════════════════╗
{ylo}        ║ {ppl}[E] {cyn}Encrypt        {ylo}║
{ylo}        ║ {ppl}[D] {blu}Decrypt        {ylo}║
{ylo}        ║ {ppl}[F] {grn}Brute Force    {ylo}║
{ylo}        ╠════════════════════╣
{ylo}        ║ {gry}[I] INFO.          {ylo}║
{ylo}        ║ {red}[B] Back           {ylo}║
{ylo}        ╚════════════════════╝

    """


def menu_morse():
    """
    Morse Code menu
    """
    return f"""
          Morse Code
{ylo}        ╔════════════════════╗
{ylo}        ║ {ppl}[E] {cyn}Encrypt        {ylo}║
{ylo}        ║ {ppl}[D] {grn}Decrypt        {ylo}║
{ylo}        ╠════════════════════╣
{ylo}        ║ {gry}[I] INFO.          {ylo}║
{ylo}        ║ {red}[B] Back           {ylo}║
{ylo}        ╚════════════════════╝

    """


def menu_bacon():
    """
    Baconian Cipher menu
    """
    return f"""
       Baconian Cipher
{ylo}        ╔════════════════════╗
{ylo}        ║ {ppl}[E] {cyn}Encrypt        {ylo}║
{ylo}        ║ {ppl}[D] {grn}Decrypt        {ylo}║
{ylo}        ╠════════════════════╣
{ylo}        ║ {gry}[I] INFO.          {ylo}║
{ylo}        ║ {red}[B] Back           {ylo}║
{ylo}        ╚════════════════════╝

    """


def error_logo(c1: str):
    """c1: Text color."""
    return f"""
{c1}    ______   ____     ____    ____     ____     __
{c1}   / ____/  / __ \\   / __ \\  / __ \\   / __ \\   / /
{c1}  / __/    / /_/ /  / /_/ / / / / /  / /_/ /  / /
{c1} / /___   / _, _/  / _, _/ / /_/ /  / _, _/  /_/
{c1}/_____/  /_/ |_|  /_/ |_|  \\____/  /_/ |_|  (_)
"""


if __name__ == "__main__":
    print("Don't run this file...")
