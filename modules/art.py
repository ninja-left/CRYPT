# -*- coding: UTF-8 -*-

from colorama import Fore as f


bl = f.BLUE
yl = f.YELLOW
gn = f.GREEN
wt = f.WHITE
mg = f.MAGENTA
rd = f.RED
cn = f.CYAN
blk = f.LIGHTBLACK_EX
rst = f.RESET


def Crypt_Logo(c1: str, c2: str, c3: str) -> None:
    """
    ---
    * c1: Big lock.
    * c2: Letters.
    * c3: "Y"-like key in the middle.
    """
    print(
        f"""
   {c1}   ▄▄████████▄▄
   {c1} ▐███▀      ▀███▌
   {c1} ██▌          ▐██  {c2}   @@@@@@@   @@@@@@@   {c3}  @   @  {c2}  @@@@@@@    @@@@@@@
   {c1}▐██            ██▌ {c2}  @@@@@@@@   @@@@@@@@  {c3} @@   @@ {c2}  @@@@@@@@   @@@@@@@
   {c1}▐█▌            ▐█▌ {c2}  !@@        @@!  @@@  {c3} @@! !@@ {c2}  @@!  @@@     @@!
   {c1}▐█▌            ▐█▌ {c2}  !@!        !@!  @!@  {c3}  @! @!  {c2}  !@!  @!@     !@!
   {c1}██████████████████ {c2}  !@!        @!@!!@!   {c3}   @!@   {c2}  @!@@!@!      @!!
   {c1}████████▀▀████████ {c2}  !!!        !!@!@!    {c3}   @!!   {c2}  !!@!!!       !!!
   {c1}███████▌  ▐███████ {c2}  :!!        !!: :!!   {c3}   !!:   {c2}  !!:          !!:
   {c1}████████  ████████ {c2}  :!:        :!:  !:!  {c3}   :!:   {c2}  :!:          :!:
   {c1}████████▄▄████████ {c2}   ::: :::   ::   :::  {c3}  ;:::   {c2}   ::           ::
   {c1}██████████████████ {c2}   :: :: :    :   : :  {c3}  ;::;   {c2}   :            :
   {c1}▐████████████████▌"""
    )


def about(c1: str, c2: str, c3: str, c4: str) -> None:
    """
    ---
    * c1: Borders.
    * c2: Normal Text.
    * c3: Developer.
    * c4: Email address.
    """
    print(
        f"""

{c1}                  ╔══════════════════════════════════════╗
{c1}                  ║     {c2}Developed by... {c3}N1nj4 R8         {c1}║
{c1}                  ║     {c2}Email: {c4}n1nj4r8@proton.me         {c1}║
{c1}                  ╚════╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦╦════╝
{c1}                       ╚╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╩╝{rst}
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
    )
