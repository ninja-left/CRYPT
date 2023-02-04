# -*- coding: utf-8 -*-

'''
    Clear Screen
    ============
    Script having functions that clear the terminal screen.

    Functions
    =========
    * cl_all: Console clear function that uses os.name.
    * cl_all_v2: Upgraded function of "cl_all" that uses "sys" module to check os.
    * cl_win: Console clear function created for windows system.
    * cl_nix: Console clear function created for *nix systems.
'''

import os
import sys


def cl_all():
    '''
    Code
    ====
    >>> command = 'clear'
    >>> if os.name in ('nt'):
    ...     command = 'cls'
    >>> os.system(command)

    Usage
    =====
    A Console clear function that does so using os.name.
    '''
    command = 'clear'
    if os.name in ('nt'):
        command = 'cls'
    os.system(command)


def cl_all_v2():
    '''
    Code
    ====
    >>> if sys.platform == 'win32':
    ...     os.system('cls')
    >>> elif sys.platform == 'linux':
    ...     os.system('clear')

    Usage
    =====
    Upgraded function of cl_all that uses "sys" to check os name.
    '''
    if sys.platform == 'win32':
        os.system('cls')
    elif sys.platform == 'linux':
        os.system('clear')


def cl_win():
    '''
    Code
    ====
    >>> os.system('cls')

    Usage
    =====
    Console clear function created for windows systems.
    '''
    os.system('cls')


def cl_nix():
    '''
    Code
    ====
    >>> os.system('clear')

    Usage
    =====
    Console clear function created for *nix systems.
    '''
    os.system('clear')
