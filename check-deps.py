#!/usr/bin/env python2
# -*- encoding: utf-8 -*-
# check_deps.py
'''
Final project for Data Communication 1 & 2.
Copyright (C) 2015 - Matías A. Ré Medina
UNICEN Systems Engineering student.
'''

import sys
import subprocess

CONST_REQUIREMENTS_FILE = "requirements.txt"

def query_user_bool(question, default=True):
    """Returns a boolean based on user input.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be True (the default), False or None (meaning
        an answer is required of the user).

    The "answer" return value is one of True or False.

    """

    valid_yes_ans = ["yes", "y"]
    valid_no_ans = ["no", "n"]

    if default is None:
        prompt = " [y/n] "
    elif default:
        prompt = " [Y/n] "
    else:
        prompt = " [y/N] "

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()

        if default is not None and choice == '':
            return default

        if choice in valid_yes_ans:
            return True

        if choice in valid_no_ans:
            return False

        sys.stdout.write("Please respond with 'yes' or 'no' "\
                             "(or 'y' or 'n').\n")

def checkDependencies(check=True):
    """Dependency resolver based on a previously specified CONST_REQUIREMENTS_FILE.

    Currently checks a list of dependencies from a file and asks for user
    confirmation on whether to install it with a specific version or not.

    """
    modules = []
    f = open(CONST_REQUIREMENTS_FILE)
    for line in f:
        if line.find('#'):
            modules.append([line[:line.index('=')], (line[line.index('=')+2:]).strip()])
    f.close()

    for module in modules:
        try:
            __import__(module[0])
        except ImportError:          
            if query_user_bool("Missing module %s." \
                    " Do you wish to install it?" % module[0]):
                    subprocess.call(["pip2", "install", "%s==%s" %
                                    (module[0], module[1])])
                
            else:
                return False
    return True

if __name__ == '__main__':
    try:
        if not checkDependencies():
            sys.exit("[!] Dependencies not met.")
        sys.stdout.write("[+] Dependencies met.\n")
    except OSError:
        sys.stdout.write("pip2 must be installed\n")
