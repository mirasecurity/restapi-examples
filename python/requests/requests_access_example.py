#!/usr/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (C) 2024 Mira Security, Inc.

import requests
import argparse
import urllib3


def connect(server_url, username=None, password=None, ssl_verify=True):
    s = requests.Session()
    if username is not None and password is not None:
        resp = s.post('%s/auth/login/' % server_url,
                      json={'username': username, 'password': password}, verify=ssl_verify)
        if resp.status_code != 200:
            raise Exception('login failed')

    return s


def list_all_users(server_url, session):
    resp = session.get('%s/users/' % server_url)
    if resp.status_code != 200:
        raise Exception('user list failed')

    for user in resp.json():
        print('%s: %s %s <%s>' % (
            user['username'], user['first_name'], user['last_name'], user['email']))


def test(server, username, password, ssl_verify):
    session = connect(server, username, password, ssl_verify)
    list_all_users(server, session)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server-url', dest='server_url', required=True,
                        help='url for the rest service.\ne.g. https://my-appliance/api')
    parser.add_argument('-u', '--username', dest='username', required=True)
    parser.add_argument('-p', '--password', dest='password', required=True)
    parser.add_argument('--noverify', action='store_true',
                        help="skip SSL verification, not recommended")
    args = parser.parse_args()

    if args.noverify:
        ssl_verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    else:
        ssl_verify = True

    test(args.server_url, args.username, args.password, ssl_verify)
