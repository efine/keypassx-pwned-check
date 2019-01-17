#!/usr/bin/env python2

"""
Usage:
  pwned [options] KEEPASSX-DB
  pwned -h | --help | -V | --version

Arguments:
  KEEPASSX-DB                        The KeePassX database to open.

Options:
  -d, --debug                        Output debug information to stderr.
  -H, --history                      Also search history entries.
  -a, --askpass                      Ask for database password.
  -F, --password-file=PASSWD-FILE    Get database password from this file.
  -k, --keyfile=KEYFILE-PATH         Path to KeePassX key file.
  -t, --title=TITLE                  Title to search for.
  -u, --username=USERNAME            Username to search for.
  -r, --regex                        Search strings (e.g. title, username) are regexes.
  -h, --help                         Show this help.
  -V, --version                      Show version.
  -v, --verbose                      Print extra information [default: False].
"""

from __future__ import print_function

__version__ = "0.1"

import hashlib
import logging
import os
import requests
import time

from getpass import getpass

try:
    from pykeepass import PyKeePass
except ImportError:
    exit('This program requires that the `pykeypass` library'
         ' is installed: \n    pip install pykeypass\n'
         'https://pypi.python.org/pypi/pykeypass/')

try:
    from docopt import docopt
except ImportError:
    exit('This program requires that the `docopt` library'
         ' is installed: \n    pip install docopt\n'
         'https://pypi.python.org/pypi/docopt/')


PWNED_URL_BASE = 'https://api.pwnedpasswords.com/range/'
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(os.path.basename(__file__))


def get_password(from_filename=None):
    if from_filename:
        with open(from_filename) as f:
            password = f.read()
    else:
        password = getpass("Enter KeePassX password: ")
    return password


def pwned_status(pwned_url_base, password):
    sha1_text = hashlib.sha1(password).hexdigest().upper()
    hash_prefix = sha1_text[0:5]
    hash_suffix = sha1_text[5:]
    url = pwned_url_base + hash_prefix
    resp = requests.get(url)
    return sha1_text if hash_suffix in resp.text else None


def main(kwargs):
    password = (
        get_password(
            kwargs["--password-file"]
                if kwargs["--askpass"]
                else None
        )
    )

    logging.info("Opening database, this might take a while...")
    kp = PyKeePass(
        kwargs["KEEPASSX-DB"],
        password=password,
        keyfile=kwargs["--keyfile"],
    )
    logging.info("Database opened.")

   #entries = kp.find_entries(
   #    title=kwargs["--title"],
   #    username=kwargs["--username"],
   #    history=kwargs["--history"],
   #    regex=kwargs["--regex"],
   #)

    entries = kp.find_entries(
        username=kwargs["--username"],
    )

    logging.info("# of entries to search for pwnage: {}".format(len(entries)))

    for n, entry in enumerate(entries, 1):
        print('{}: {}'.format(n, entry.title), end=' ')
        ps = pwned_status(PWNED_URL_BASE, entry.password)
        if ps:
            print('PWNED!! (password: {})'.format(entry.password))
        else:
            print('OK')

    logging.info("Done.")

if __name__ == '__main__':
    prog, _ = os.path.splitext(os.path.basename(__file__))
    arguments = docopt(__doc__,
                       version='{} {}'.format(prog, __version__),
                       options_first=True)

    if arguments["--verbose"]:
        logger.setLevel(logging.INFO)
        logger.info("\n{}\n".format(arguments))

    if arguments["--debug"]:
        logger.setLevel(logging.DEBUG)

    main(arguments)


# vim: tw=68 ft=python syntax=python ts=4 sts=4 sw=4 et :
