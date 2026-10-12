#!/usr/bin/env python3
"""
Root-owned helper: checks a username/password pair against Linux system
accounts via PAM. Must run as root because pam_unix's unix_chkpwd helper
refuses to verify another user's password otherwise. Invoked by the admin
web app via a narrowly-scoped sudo rule (see sudoers.template); the calling
password is passed over stdin, never as a command-line argument, so it never
appears in `ps` output or sudo logs.

Usage: rasp-proxy-pamcheck <username>   (password read from stdin)
Exit 0 = authenticated, exit 1 = rejected, exit 2 = bad usage.
"""
import sys

import PAM

PAM_SERVICE = "rasp-proxy-admin"


def main():
    if len(sys.argv) != 2:
        sys.exit(2)
    username = sys.argv[1]
    password = sys.stdin.buffer.read().decode()

    def conv(auth, query_list, user_data):
        return [(password, 0) for _ in query_list]

    auth = PAM.pam()
    auth.start(PAM_SERVICE)
    auth.set_item(PAM.PAM_USER, username)
    auth.set_item(PAM.PAM_CONV, conv)
    try:
        auth.authenticate()
        auth.acct_mgmt()
        sys.exit(0)
    except PAM.error:
        sys.exit(1)


if __name__ == "__main__":
    main()
