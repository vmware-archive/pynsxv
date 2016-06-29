#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2015-2016 VMware, Inc. All Rights Reserved.
#
# Licensed under the X11 (MIT) (the “License”) set forth below;
#
# you may not use this file except in compliance with the License. Unless required by applicable law or agreed to in
# writing, software distributed under the License is distributed on an “AS IS” BASIS, without warranties or conditions
# of any kind, EITHER EXPRESS OR IMPLIED. See the License for the specific language governing permissions and
# limitations under the License. Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
# Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.
#
# "THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.”

__author__ = 'yfauser'

import argparse
import ConfigParser
import json
from tabulate import tabulate
from libutils import check_for_parameters, get_edge
from nsxramlclient.client import NsxClient
from argparse import RawTextHelpFormatter
from pkg_resources import resource_filename


def add_dhcp_pool(client_session, esg_name, dhcp_pool_dict):
    """
    :param client_session: An instance of an NsxClient Session
    :param ip_pool_dict: A dictionaries containing the Pool Information with the following keys:
             ipRange = IP Range e.g. 192.168.5.2-192.168.5.20
             defaultGateway = The def gateway for the Network, e.g. 192.168.5.1
             subnetMask = The Subnet Mask for the Network
             domainName = The dns domain name, e.g. vmware.com (optional)
             primaryNameServer = The first DNS Server (optional)
             secondaryNameServer = The second DNS Server (optional)
             leaseTime = The lease time (optional), use 'infinite' for no expiry
             autoConfigureDNS = Use the DNS servers configured for NSX-Manager for this Pool (optional)
    :return: True if the configuration succeeded
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    result = client_session.create('dhcpPool', uri_parameters={'edgeId': esg_id},
                                   request_body_dict={'ipPool': dhcp_pool_dict})
    if result['status'] != 204:
        return None
    else:
        return result['objectId']

def _add_dhcp_pool(client_session, **kwargs):
    needed_params = ['esg_name', 'ip_range']
    if not check_for_parameters(needed_params, kwargs):
        return None

    if kwargs['auto_dns'] != 'true':
        auto_dns = 'false'
    else:
        auto_dns = 'true'

    dhcp_pool_dict = {'ipRange': kwargs['ip_range'],
                    'defaultGateway': kwargs['default_gateway'],
                    'subnetMask': kwargs['subnet_mask'],
                    'domainName': kwargs['domain_name'],
                    'primaryNameServer': kwargs['dns_server_1'],
                    'secondaryNameServer': kwargs['dns_server_2'],
                    'leaseTime': kwargs['lease_time'],
                    'autoConfigureDNS': auto_dns}

    result = add_dhcp_pool(client_session, kwargs['esg_name'], dhcp_pool_dict)

    if result and kwargs['verbose']:
        print result
    elif result:
        print 'IP Pool configuration on esg {} succeeded, the DHCP Pool Id is {}'.format(kwargs['esg_name'], result)
    else:
        print 'IP Pool configuration on esg {} failed'.format(kwargs['esg_name'])


def dhcp_server(client_session, esg_name, enabled=None, syslog_enabled=None, syslog_level=None):
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    change_needed = False

    current_dhcp_config = client_session.read('dhcp', uri_parameters={'edgeId': esg_id})['body']
    new_dhcp_config = current_dhcp_config

    if enabled:
        if current_dhcp_config['dhcp']['enabled'] == 'false':
            new_dhcp_config['dhcp']['enabled'] = 'true'
            change_needed = True
    else:
        if current_dhcp_config['dhcp']['enabled'] == 'true':
            new_dhcp_config['dhcp']['enabled'] = 'false'
            change_needed = True

    if syslog_enabled == 'true':
        if current_dhcp_config['dhcp']['logging']['enable'] == 'false':
            new_dhcp_config['dhcp']['logging']['enable'] = 'true'
            change_needed = True
    elif syslog_enabled == 'false':
        if current_dhcp_config['dhcp']['logging']['enable'] == 'true':
            new_dhcp_config['dhcp']['logging']['enable'] = 'false'
            change_needed = True

    if syslog_level:
        if current_dhcp_config['dhcp']['logging']['logLevel'] != syslog_level:
            new_dhcp_config['dhcp']['logging']['logLevel'] = syslog_level
            change_needed = True

    if not change_needed:
        return True
    else:
        result = client_session.update('dhcp', uri_parameters={'edgeId': esg_id},
                                       request_body_dict=new_dhcp_config)
        if result['status'] == 204:
            return True
        else:
            return False


def _enable_server(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = dhcp_server(client_session, kwargs['esg_name'], enabled=True, syslog_enabled=kwargs['logging'],
                         syslog_level=kwargs['log_level'])

    if not result:
        print 'Enabling DHCP on Edge Services Gateway {} failed'.format(kwargs['esg_name'])
    else:
        print 'Enabling DHCP on Edge Services Gateway {} succeeded'.format(kwargs['esg_name'])


def _disable_server(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = dhcp_server(client_session, kwargs['esg_name'], enabled=False)

    if not result:
        print 'Disabling DHCP on Edge Services Gateway {} failed'.format(kwargs['esg_name'])
    else:
        print 'Disabling DHCP on Edge Services Gateway {} succeeded'.format(kwargs['esg_name'])


def read(client_session, esg_name):
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    dhcp_status = client_session.read('dhcp', uri_parameters={'edgeId': esg_id})['body']
    return dhcp_status


def _read(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = read(client_session, kwargs['esg_name'])

    if result and kwargs['verbose']:
        print json.dumps(result)
    elif result:
        print tabulate([(result['dhcp']['enabled'],
                        result['dhcp']['logging']['enable'],
                        result['dhcp']['logging']['logLevel'])],
                       headers=["DHCP Enabled", "Logging Enabled", "Log Level"],
                       tablefmt="psql")
    else:
        print 'Failed to get DHCP status from Edge Services Gateway {}'.format(kwargs['esg_name'])


def contruct_parser(subparsers):
    parser = subparsers.add_parser('dhcp', description="Functions for DHCP configurations on Edge Service Gateways",
                                   help="Functions for Edge DHCP",
                                   formatter_class=RawTextHelpFormatter)

    parser.add_argument("command", help="""
    enable_server:  Enables the edge DHCP server and configures its logging status and level
    disable_server: Disables the edge DHCP server
    read:           Retrieve the status and read the config of the edge DHCP Service on the edge
    add_pool:       adds an DHCP Pool to the edge DHCP Server
    """)

    parser.add_argument("-n",
                        "--esg_name",
                        help="ESG name")
    parser.add_argument("-lg",
                        "--logging",
                        help="Logging status for DHCP (true/false)")
    parser.add_argument("-ll",
                        "--log_level",
                        help="Log level for DHCP")
    parser.add_argument("-ipr",
                        "--ip_range",
                        help="IP Range, used when creating a DHCP pool, e.g. 192.168.5.2-192.168.5.20")
    parser.add_argument("-dgw",
                        "--default_gateway",
                        help="The def gateway for the Network when creating a DHCP pool or static host entry, "
                             "e.g. 192.168.5.1")
    parser.add_argument("-mask",
                        "--subnet_mask",
                        help="The Subnet Mask for the Network when creating a DHCP pool or static host entry, "
                             "e.g. 255.255.255.0")
    parser.add_argument("-dmn",
                        "--domain_name",
                        help="The dns domain name for the Network when creating a DHCP poolor static host entry, "
                             "e.g. vmware.com")
    parser.add_argument("-dns1",
                        "--dns_server_1",
                        help="The first DNS server for the Network when creating a DHCP pool or static host entry")
    parser.add_argument("-dns2",
                        "--dns_server_2",
                        help="The second DNS server for the Network when creating a DHCP pool or static host entry")
    parser.add_argument("-le",
                        "--lease_time",
                        help="The lease time for the Network when creating a DHCP pool or static host entry, use "
                             "'infinite' if you don't want the lease to expire")
    parser.add_argument("-au",
                        "--auto_dns",
                        help="Use the DNS servers configured for NSX-Manager for this Pool or static host entry "
                             "(true/false)")

    parser.set_defaults(func=_dhcp_main)

def _dhcp_main(args):
    if args.debug:
        debug = True
    else:
        debug = False

    config = ConfigParser.ConfigParser()
    assert config.read(args.ini), 'could not read config file {}'.format(args.ini)

    try:
        nsxramlfile = config.get('nsxraml', 'nsxraml_file')
    except (ConfigParser.NoSectionError):
        nsxramlfile_dir = resource_filename(__name__, 'api_spec')
        nsxramlfile = '{}/nsxvapi.raml'.format(nsxramlfile_dir)

    client_session = NsxClient(nsxramlfile, config.get('nsxv', 'nsx_manager'),
                               config.get('nsxv', 'nsx_username'), config.get('nsxv', 'nsx_password'), debug=debug)

    try:
        command_selector = {
            'enable_server': _enable_server,
            'disable_server': _disable_server,
            'read': _read,
            'add_pool': _add_dhcp_pool,
            }
        command_selector[args.command](client_session, esg_name=args.esg_name, logging=args.logging,
                                       log_level=args.log_level, ip_range=args.ip_range,
                                       default_gateway=args.default_gateway, subnet_mask=args.subnet_mask,
                                       domain_name=args.domain_name, dns_server_1=args.dns_server_1,
                                       dns_server_2=args.dns_server_2, lease_time=args.lease_time,
                                       auto_dns=args.auto_dns, verbose=args.verbose)
    except KeyError as e:
        print('Unknown command: {}'.format(e))


def main():
    main_parser = argparse.ArgumentParser()
    subparsers = main_parser.add_subparsers()
    contruct_parser(subparsers)
    args = main_parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
