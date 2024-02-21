#!/usr/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (C) 2024 Mira Security, Inc.

import requests
import argparse
import urllib3


def list_health(server_url, token, ssl_verify):
    resp = requests.get('%s/system/info/health/' % server_url,
                        headers={'Authorization': 'Token %s' % token}, verify=ssl_verify)
    if resp.status_code != 200:
        raise Exception('list health failed')

    for service in resp.json():
        print("%s: %s" % (service['name'], service['status']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server-url', dest='server_url', required=True,
                        help='url for the rest service.\ne.g. https://my-appliance/api')
    parser.add_argument('-t', '--token', dest='token', required=True)
    parser.add_argument('--noverify', action='store_true',
                        help="skip SSL verification, not recommended")
    args = parser.parse_args()

    if args.noverify:
        ssl_verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    else:
        ssl_verify = True

    list_health(args.server_url, args.token, ssl_verify)
