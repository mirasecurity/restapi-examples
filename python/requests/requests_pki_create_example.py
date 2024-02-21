#!/usr/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (C) 2024 Mira Security, Inc.

import requests
import argparse
import urllib3
from http.cookiejar import MozillaCookieJar


def connect(server_url, username=None, password=None, ssl_verify=True):
    s = requests.Session()
    if username is not None and password is not None:
        resp = s.post('%s/auth/login/' % server_url,
                      json={'username': username, 'password': password},
                      verify=ssl_verify,
                      cookies=MozillaCookieJar())
        if resp.status_code != 200:
            raise Exception(
                f'Login failed:\n{resp.status_code} - {resp.reason}\nResponse: {resp.text}')

    return s


def upload_endpoint_pki(server_url, session, pki_path=None):

    with open(pki_path, 'r') as pem_data:
        pem_contents = pem_data.read()

    # Strip out newline and other extraneous characters
    pem_contents.strip()

    # Find start and end of certificate block
    cert_start = pem_contents.find('-----BEGIN CERTIFICATE-----')
    cert_end = pem_contents.find(
        '-----END CERTIFICATE-----') + len('-----END CERTIFICATE-----')

    # Find start and end of private key block
    if pem_contents.find('-----BEGIN RSA PRIVATE KEY-----') != -1:
        key_start = pem_contents.find('-----BEGIN RSA PRIVATE KEY-----')
        key_end = pem_contents.find(
            '-----END RSA PRIVATE KEY-----') + len('-----END RSA PRIVATE KEY-----')
    elif pem_contents.find('-----BEGIN PRIVATE KEY-----') != -1:
        key_start = pem_contents.find('-----BEGIN PRIVATE KEY-----')
        key_end = pem_contents.find(
            '-----END PRIVATE KEY-----') + len('-----END PRIVATE KEY-----')
    # Save the PKI data to different variables
    if all(pki_index != -1 for pki_index in [cert_start, cert_end, key_start, key_end]):
        cert_data = pem_contents[cert_start:cert_end]
        key_data = pem_contents[key_start:key_end]
    else:
        raise Exception('pemfile could not be read')

    # Define the PKI Payload
    pki_args = dict()
    pki_args['pki_type'] = 'endpoint'
    pki_args['pki_lists'] = []
    pki_args['data_entries'] = [{
        'data_type': 'x509.crt',
        'encoding': 'pem',
        'value': cert_data,
    }, {
        'data_type': 'key',
        'encoding': 'pem',
        'value': key_data,
    }]

    resp = session.post('%s/pki/' % server_url, json=pki_args)
    if resp.status_code != 201:
        raise Exception(
            f'PKI Upload Failed:\n{resp.status_code} - {resp.reason}\nResponse: {resp.text}')
    else:
        print("Certificate and key added to PKI store, cert details: %s " %
              resp.json()['summary'])


def test(server, username, password, pki_path, ssl_verify):
    session = connect(server, username, password, ssl_verify)
    upload_endpoint_pki(server, session, pki_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server-url', dest='server_url', required=True,
                        help='url for the rest service.\ne.g. https://my-appliance/api')
    parser.add_argument('-u', '--username', dest='username', required=True)
    parser.add_argument('-p', '--password', dest='password', required=True)
    parser.add_argument('-i', '--input-file', dest='pki_path', required=True,
                        help='path to the pemFile containing the endpoint Certificate')
    parser.add_argument('--noverify', action='store_true',
                        help='skip SSL verification, not recommended')

    args = parser.parse_args()

    if args.noverify:
        ssl_verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    else:
        ssl_verify = True

    test(args.server_url, args.username,
         args.password, args.pki_path, ssl_verify)
