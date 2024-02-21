#!/usr/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (C) 2024 Mira Security, Inc.

import sys
import base64
import uuid
import argparse
import time
import urllib3
import urllib
import json
import ssl

from bravado.requests_client import RequestsClient
from bravado.client import SwaggerClient, SwaggerFormat
import bravado.exception

# helper to connect to the rest backend and authenticate


def connect(server_url, username=None, password=None, ssl_verify=True):
    if not ssl_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    http_client = RequestsClient(ssl_verify=ssl_verify)
    swagger_client = SwaggerClient.from_url(
        '%s/swagger.json' % server_url,
        http_client=http_client,
        config={
            'validate_responses': False,
            'validate_requests': True,
            'validate_swagger_spec': False,
            'use_models': False,
            'formats': [
                SwaggerFormat(
                    format='uri',
                    to_wire=lambda b: b if isinstance(b, str) else str(b),
                    to_python=lambda s: s if isinstance(s, str) else str(s),
                    validate=lambda v: v,
                    description='Converts [wire]string:byte <=> python byte',
                ),
                SwaggerFormat(
                    format='email',
                    to_wire=lambda b: b if isinstance(b, str) else str(b),
                    to_python=lambda s: s if isinstance(s, str) else str(s),
                    validate=lambda v: v,
                    description='Converts [wire]string:byte <=> python byte',
                ),
                SwaggerFormat(
                    format='ipv4',
                    to_wire=lambda b: b if isinstance(b, str) else str(b),
                    to_python=lambda s: s if isinstance(s, str) else str(s),
                    validate=lambda v: v,
                    description='Converts [wire]string:byte <=> python byte',
                ),
                SwaggerFormat(
                    format='ipv6',
                    to_wire=lambda b: b if isinstance(b, str) else str(b),
                    to_python=lambda s: s if isinstance(s, str) else str(s),
                    validate=lambda v: v,
                    description='Converts [wire]string:byte <=> python byte',
                ),
            ],
        },
    )

    if username is not None and password is not None:
        login = swagger_client.auth.auth_login_create(
            data=swagger_client.get_model('Login')(
                username=username, password=password)
        ).response().result

    swagger_client.server_url = server_url

    return swagger_client

# various examples


def poll_task(client, id, task_desc):
    while True:
        task_status = client.tasks.tasks_read(id=id).response().result
        if task_status['status'] == 'error':
            raise Exception('%s failed: %s' %
                            (task_desc, task_status['error']))
        elif task_status['status'] == 'completed':
            print('%s completed: %s' % (task_desc, task_status['result']))
            return task_status
        else:
            print('%s progress: %s%%' %
                  (task_desc, task_status['progress']*100))

        time.sleep(1)


def list_all_users(client):
    # print out user info
    users = client.users.users_list().response().result
    for user in users:
        print('%s: %s %s <%s>' % (user['username'], user['first_name'],
                                  user['last_name'], user['email']))


def add_full_policy(client, uid):
    # create internal ca
    new_pki = client.pki.pki_create(
        data=client.get_model('PKI')(
            pki_type='internal-ca',
            data_entries=[],
            csr_data={
                'common_name': 'test',
                'self_signed': True,
            },
        )
    ).response().result

    # create ip matchlist and entry
    new_matchlist = client.matchlists.matchlists_create(
        data=client.get_model('MatchList')(
            name='ip matchlist: %s' % uid,
            list_type='ip',
        )
    ).response().result
    new_matchpattern = client.matchpatterns.matchpatterns_create(
        data=client.get_model('MatchPattern')(
            value='1.2.3.4',
            pattern_type='exact',
            match_list=new_matchlist['url'],
        )
    ).response().result

    # create policy
    new_policy = client.policies.policies_create(
        data=client.get_model('Policy')(
            name='policy: %s' % uid,
            catch_all_action='cut',
            catch_all_error_action='drop',
            catch_all_pki=new_pki['url'],
        )
    ).response().result

    # create rule list
    new_rulelist = client.rulelists.rulelists_create(
        data=client.get_model('RuleList')(
            name='rulelist: %s' % uid,
            rules=[],
            policies=[],
        )
    ).response().result

    # link policy and rulelist
    new_policy_rulelist = client.policyrulelists.policyrulelists_create(
        data=client.get_model('PolicyRuleList')(
            policy=new_policy['url'],
            rule_list=new_rulelist['url'],
        )
    ).response().result

    # add a rule
    new_rule = client.rules.rules_create(
        data=client.get_model('Rule')(
            action='drop',
            error_action='reject',
            src_ip_list=new_matchlist['url'],
            rule_list=new_rulelist['url'],
            cert_categories=[],
            sni_categories=[],
            category_match_mode='auto',
            server_categories=[],
        )
    ).response().result

    print('policy added: %s' % new_policy['url'])

    return new_policy['url']


def add_and_activate_segment(client, uid, policy):
    # get nic info
    hw_info = client.segments.segments_hardware_discovery().response().result

    if not hw_info['cards']:
        raise Exception('no cards found on system.')

    first_card = hw_info['cards'][0]

    # create segment
    new_segment = client.segments.segments_create(
        data=client.get_model('Segment')(
            name='segment: %s' % uid,
            policy=policy,
            mode='net-inline/app-passive/port-per-dir',
            ports=[],
            plaintext_marks=[],
            vlan_mappings=[],
            logical_slot=first_card['logical_slot'],
            generated_max_packet_size=0,
            prevent_mirroring_mac='00:00:00:00:00:00',
            vlan_map_src_mac_tls='00:00:00:00:00:00',
            vlan_map_src_mac_tls_default_enabled=False,
            vlan_map_src_mac_ssh='00:00:00:00:00:00',
            vlan_map_src_mac_ssh_default_enabled=False,
        )
    ).response().result

    print('segment added: %s' % new_segment['url'])

    # activate segment and poll the task until finished
    activate_task = client.segments.segments_activate(
        data=client.get_model('SegmentActivate')(
            activate_segments=[new_segment['id']],
            deactivate_segments=[],
            confirm=True,
        )
    ).response().result

    poll_task(client, activate_task['task_id'], 'activation')

    return new_segment['id']


def deactivate_all_segments(client):
    segments = client.segments.segments_list().response().result
    deactivate_segments = [segment['id']
                           for segment in segments if segment['enabled']]
    if deactivate_segments:
        deactivate_task = client.segments.segments_activate(
            data=client.get_model('SegmentActivate')(
                activate_segments=[],
                deactivate_segments=deactivate_segments,
                confirm=True,
            )
        ).response().result
        poll_task(client, deactivate_task['task_id'], 'deactivation')


def backup_policy_pki(client, filename, noverify):
    # backup policy/pki data and save to file
    result_task = client.system.system_actions_backup_update(
        data=client.get_model('SystemActionsBackup')(
            filter=['policies.policy_pki'],
        )
    ).response().result
    backup_task = poll_task(client, result_task['task_id'], 'backup')
    backup_result = json.loads(backup_task['result'])
    # download backup archive from the url in the result
    server_url_res = urllib.parse.urlparse(client.server_url)
    download_url = '%s://%s%s' % (server_url_res.scheme,
                                  server_url_res.netloc, backup_result['url'])
    context = ssl._create_unverified_context() if noverify else None
    # for the authenticated download, the ntd_jwt cookie needs to be added
    ntd_jwt = client.auth.auth_jwt_list().response().result['detail']
    request = urllib.request.Request(download_url)
    request.add_header('Cookie', 'ntd_jwt=%s' % ntd_jwt)
    with urllib.request.urlopen(request, context=context) as response:
        if response.status == 200:
            data = response.read()
        else:
            raise Exception('Error %s:%s downloading %s' % (
                            response.status, response.reason, download_url))

    with open(filename, 'wb') as f:
        f.write(data)

    print('backed up to: %s' % filename)

    return backup_result['password']


def restore_policy_pki(client, filename, password):
    # restore policy/pki data from file
    with open(filename, 'rb') as f:
        backup_data = base64.b64encode(f.read()).decode()
    result_task = client.system.system_actions_restore_update(
        data=client.get_model('SystemActionsRestore')(
            data=backup_data,
            password=password,
            filter=['policies.policy_pki'],
        )
    ).response().result
    restore_task = poll_task(client, result_task['task_id'], 'restore')
    restore_result = json.loads(restore_task['result'])

    print('restored: %s\n%s' %
          (restore_task['summary'], restore_result['message']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server-url', dest='server_url', required=True,
                        help='url for the rest service.\ne.g. https://my-appliance/api for '
                             'external access or http://localhost:8000 for internal access.')
    parser.add_argument('-u', '--username', dest='username', required=True)
    parser.add_argument('-p', '--password', dest='password', required=True)
    parser.add_argument('-n', '--noverify', dest='noverify', default=False, action='store_true',
                        help='do not require a signed certificate')
    parser.add_argument('-d', '--debug', dest='debug', default=False, action='store_true',
                        help=argparse.SUPPRESS)

    subparsers = parser.add_subparsers(dest='subparser', help='tests')
    subparsers.add_parser('all', help='all tests')
    subparsers.add_parser('users', help='list all users')
    subparsers.add_parser('policy', help='add policy/pki/segment and activate')
    subparsers.add_parser(
        'backup-restore', help='backup and restore appliance data to an archive')

    args = parser.parse_args()

    try:
        client = connect(args.server_url, args.username,
                         args.password, not args.noverify)

        if args.subparser is None:
            raise Exception('please provide a test to run, see --help')

        if args.subparser in ('all', 'users'):
            list_all_users(client)

        if args.subparser in ('all', 'policy'):
            uid = str(uuid.uuid4())
            policy = add_full_policy(client, uid)
            add_and_activate_segment(client, uid, policy)

        if args.subparser in ('all', 'backup-restore'):
            password = backup_policy_pki(client, './temp.zip', args.noverify)
            deactivate_all_segments(client)
            restore_policy_pki(client, './temp.zip', password)

    except bravado.exception.HTTPBadRequest as err:
        try:
            msg = err.response.json()
        except Exception as json_err:
            msg = err

        print('Validation Error: %s' % str(err))
        sys.exit(1)

    except bravado.exception.HTTPInternalServerError as error:
        if error.response.text:
            msg = error.response.text
        else:
            msg = error.response.reason

        print('Server Error: %s' % msg)
        sys.exit(1)

    except bravado.exception.BravadoConnectionError as err:
        if type(err).__name__ == 'RequestsFutureAdapterConnectionError' and err.__context__ is not None:
            err = err.__context__
        print('Connection Error: %s' % str(err))
        sys.exit(1)

    except Exception as err:
        if args.debug:
            raise
        else:
            print('Unhandled Error: %s: %s' % (type(err).__name__, str(err)))
            sys.exit(1)
