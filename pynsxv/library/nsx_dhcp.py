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

import argparse
import ConfigParser
import json
from tabulate import tabulate
from libutils import check_for_parameters, get_edge, get_vm_by_name, connect_to_vc
from nsxramlclient.client import NsxClient
from argparse import RawTextHelpFormatter
from pkg_resources import resource_filename


__author__ = 'yfauser'


def add_dhcp_pool(client_session, esg_name, ip_range, default_gateway=None, subnet_mask=None, domain_name=None,
                  dns_server_1=None, dns_server_2=None, lease_time=None, auto_dns=None):
    """
    This function adds a DHCP Pool to an edge DHCP Server

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for DHCP
    :type ip_range: str
    :param ip_range: An IP range, e.g. 192.168.178.10-192.168.178.100 for this IP Pool
    :type default_gateway: str
    :param default_gateway: The default gateway for the specified subnet
    :type subnet_mask: str
    :param subnet_mask: The subnet mask (e.g. 255.255.255.0) for the specified subnet
    :type domain_name: str
    :param domain_name: The DNS domain name (e.g. vmware.com) for the specified subnet
    :type dns_server_1: str
    :param dns_server_1: The primary DNS Server
    :type dns_server_2: str
    :param dns_server_2: The secondary DNS Server
    :type lease_time: str
    :param lease_time: The lease time in seconds, use 'infinite' to disable expiry of DHCP leases
    :type auto_dns: str
    :param auto_dns: ('true'/'false') If set to true, the DNS servers and domain name set for NSX-Manager will be used
    :rtype: str
    :return: Returns a string containing the pool id of the created DHCP Pool
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    dhcp_pool_dict = {'ipRange': ip_range,
                      'defaultGateway': default_gateway,
                      'subnetMask': subnet_mask,
                      'domainName': domain_name,
                      'primaryNameServer': dns_server_1,
                      'secondaryNameServer': dns_server_2,
                      'leaseTime': lease_time,
                      'autoConfigureDNS': auto_dns}

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

    result = add_dhcp_pool(client_session, kwargs['esg_name'], kwargs['ip_range'],
                           default_gateway=kwargs['default_gateway'], subnet_mask=kwargs['subnet_mask'],
                           domain_name=kwargs['domain_name'], dns_server_1=kwargs['dns_server_1'],
                           dns_server_2=kwargs['dns_server_2'], lease_time=kwargs['lease_time'], auto_dns=auto_dns)

    if result and kwargs['verbose']:
        print result
    elif result:
        print 'IP Pool configuration on esg {} succeeded, the DHCP Pool Id is {}'.format(kwargs['esg_name'], result)
    else:
        print 'IP Pool configuration on esg {} failed'.format(kwargs['esg_name'])


def list_dhcp_pools(client_session, esg_name):
    """
    This function lists all DHCP Pools on an edge DHCP Server

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for DHCP
    :rtype: tuple
    :return: Returns a tuple with the first item being a list of tuples containing:

             [0] Pool Id
             [1] IP Range
             [2] Default Gateway
             [3] Subnet Mask
             [4] Domain Name
             [5] Primary DNS Server
             [6] Secondary DNS Server
             [7] Lease Time
             [8] Autoconfigure DNS (true/false),

             The second item contains a list of dicts with all the pool details as returned by the NSX API
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None, None

    result = client_session.read('dhcp', uri_parameters={'edgeId': esg_id})
    if not result['body']['dhcp']['ipPools']:
        return [], []

    ip_pools = client_session.normalize_list_return(result['body']['dhcp']['ipPools']['ipPool'])

    pool_list = [(pool.get('poolId'), pool.get('ipRange'), pool.get('defaultGateway'), pool.get('subnetMask'),
                  pool.get('domainName'), pool.get('primaryNameServer'), pool.get('secondaryNameServer'),
                  pool.get('leaseTime'), pool.get('autoConfigureDNS')) for pool in ip_pools]

    pool_list_verbose = [pool for pool in ip_pools]

    return pool_list, pool_list_verbose


def _list_dhcp_pools(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    ip_pool_list, ip_pool_verbose = list_dhcp_pools(client_session, kwargs['esg_name'])

    if kwargs['verbose']:
        print json.dumps(ip_pool_verbose)
    else:
        print tabulate(ip_pool_list, headers=["Pool ID", "IP Range", "Gateway", "Subnet Mask", "Domain Name",
                                              "DNS 1", "DNS 2", "Lease Time", "Auto Config DNS"], tablefmt="psql")


def delete_dhcp_pool(client_session, esg_name, pool_id):
    """
    This function deletes a DHCP Pools from an edge DHCP Server

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for DHCP
    :type pool_id: str
    :param pool_id: The Id of the pool to be deleted (e.g. pool-3)
    :rtype: bool
    :return: Returns None if Edge was not found or the operation failed, returns true on success
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    result = client_session.delete('dhcpPoolID', uri_parameters={'edgeId': esg_id, 'poolID': pool_id})

    if result['status'] == 204:
        return True
    else:
        return None


def _delete_dhcp_pool(client_session, **kwargs):
    needed_params = ['esg_name', 'pool_id']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = delete_dhcp_pool(client_session, kwargs['esg_name'], kwargs['pool_id'])

    if result:
        print 'Deleting IP Pool {} on esg {} succeeded'.format(kwargs['pool_id'], kwargs['esg_name'])
    else:
        print 'Deleting IP Pool {} on esg {} failed'.format(kwargs['pool_id'], kwargs['esg_name'])


def add_mac_binding(client_session, esg_name, mac, hostname, ip, default_gateway=None, subnet_mask=None,
                    domain_name=None, dns_server_1=None, dns_server_2=None, lease_time=None, auto_dns=None):
    """
    This function add a MAC based static binding entry to an edge DHCP Server

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for DHCP
    :type mac: str
    :param mac: The MAC Address of the static binding
    :type hostname: str
    :param hostname: The hostname for this static binding
    :type ip: str
    :param ip: The IP Address for this static binding
    :type default_gateway: str
    :param default_gateway: The default gateway for the specified binding
    :type subnet_mask: str
    :param subnet_mask: The subnet mask (e.g. 255.255.255.0) for the specified binding
    :type domain_name: str
    :param domain_name: The DNS domain name (e.g. vmware.com) for the specified binding
    :type dns_server_1: str
    :param dns_server_1: The primary DNS Server
    :type dns_server_2: str
    :param dns_server_2: The secondary DNS Server
    :type lease_time: str
    :param lease_time: The lease time in seconds, use 'infinite' to disable expiry of DHCP leases
    :type auto_dns: str
    :param auto_dns: ('true'/'false') If set to true, the DNS servers and domain name set for NSX-Manager will be used
    :rtype: str
    :return: Returns a string containing the binding id of the created DHCP binding
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    binding_dict = {'macAddress': mac, 'hostname': hostname, 'ipAddress': ip, 'defaultGateway': default_gateway,
                    'subnetMask': subnet_mask, 'domainName': domain_name, 'primaryNameServer': dns_server_1,
                    'secondaryNameServer': dns_server_2, 'leaseTime': lease_time, 'autoConfigureDNS': auto_dns}

    result = client_session.create('dhcpStaticBinding', uri_parameters={'edgeId': esg_id},
                                   request_body_dict={'staticBinding': binding_dict})
    if result['status'] != 204:
        return None
    else:
        return result['objectId']


def _add_mac_binding(client_session, **kwargs):
    needed_params = ['esg_name', 'mac', 'hostname', 'ip']
    if not check_for_parameters(needed_params, kwargs):
        return None

    if kwargs['auto_dns'] != 'true':
        auto_dns = 'false'
    else:
        auto_dns = 'true'

    result = add_mac_binding(client_session, kwargs['esg_name'], kwargs['mac'], kwargs['hostname'], kwargs['ip'],
                             default_gateway=kwargs['default_gateway'], subnet_mask=kwargs['subnet_mask'],
                             domain_name=kwargs['domain_name'], dns_server_1=kwargs['dns_server_1'],
                             dns_server_2=kwargs['dns_server_2'], lease_time=kwargs['lease_time'], auto_dns=auto_dns)

    if result and kwargs['verbose']:
        print result
    elif result:
        print 'Static binding configuration on esg {} succeeded, the Binding Id is {}'.format(kwargs['esg_name'],
                                                                                              result)
    else:
        print 'Static binding configuration on esg {} failed'.format(kwargs['esg_name'])


def add_vm_binding(client_session, esg_name, vm_id, vnic_id, hostname, ip, default_gateway=None, subnet_mask=None,
                   domain_name=None, dns_server_1=None, dns_server_2=None, lease_time=None, auto_dns=None):
    """
    This function add a VM based static binding entry to an edge DHCP Server

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for DHCP
    :type vm_id: str
    :param vm_id: The VM managed object Id in vCenter for the VM to be attached to this binding entry
    :type vnic_id: str
    :param vnic_id: The vnic index for the VM interface attached to this binding entry (e.g. vnic0 has index 0)
    :type hostname: str
    :param hostname: The hostname for this static binding
    :type ip: str
    :param ip: The IP Address for this static binding
    :type default_gateway: str
    :param default_gateway: The default gateway for the specified binding
    :type subnet_mask: str
    :param subnet_mask: The subnet mask (e.g. 255.255.255.0) for the specified binding
    :type domain_name: str
    :param domain_name: The DNS domain name (e.g. vmware.com) for the specified binding
    :type dns_server_1: str
    :param dns_server_1: The primary DNS Server
    :type dns_server_2: str
    :param dns_server_2: The secondary DNS Server
    :type lease_time: str
    :param lease_time: The lease time in seconds, use 'infinite' to disable expiry of DHCP leases
    :type auto_dns: str
    :param auto_dns: ('true'/'false') If set to true, the DNS servers and domain name set for NSX-Manager will be used
    :rtype: str
    :return: Returns a string containing the binding id of the created DHCP binding
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    binding_dict = {'vmId': vm_id, 'vnicId': vnic_id, 'hostname': hostname, 'ipAddress': ip,
                    'defaultGateway': default_gateway, 'subnetMask': subnet_mask, 'domainName': domain_name,
                    'primaryNameServer': dns_server_1, 'secondaryNameServer': dns_server_2, 'leaseTime': lease_time,
                    'autoConfigureDNS': auto_dns}

    result = client_session.create('dhcpStaticBinding', uri_parameters={'edgeId': esg_id},
                                   request_body_dict={'staticBinding': binding_dict})
    if result['status'] != 204:
        return None
    else:
        return result['objectId']


def _add_vm_binding(client_session, vccontent, **kwargs):
    needed_params = ['esg_name', 'vm_name', 'vnic_id', 'hostname', 'ip']
    if not check_for_parameters(needed_params, kwargs):
        return None

    if kwargs['auto_dns'] != 'true':
        auto_dns = 'false'
    else:
        auto_dns = 'true'

    vm_id = get_vm_by_name(vccontent, kwargs['vm_name'])
    if not vm_id:
        print 'Static binding configuration on esg {} failed, VM {} not found'.format(kwargs['esg_name'],
                                                                                      kwargs['vm_name'])
        return None

    result = add_vm_binding(client_session, kwargs['esg_name'], vm_id, kwargs['vnic_id'],
                            kwargs['hostname'], kwargs['ip'], default_gateway=kwargs['default_gateway'],
                            subnet_mask=kwargs['subnet_mask'], domain_name=kwargs['domain_name'],
                            dns_server_1=kwargs['dns_server_1'], dns_server_2=kwargs['dns_server_2'],
                            lease_time=kwargs['lease_time'], auto_dns=auto_dns)

    if result and kwargs['verbose']:
        print result
    elif result:
        print 'Static binding configuration on esg {} succeeded, the Binding Id is {}'.format(kwargs['esg_name'],
                                                                                              result)
    else:
        print 'Static binding configuration on esg {} failed'.format(kwargs['esg_name'])


def list_dhcp_bindings(client_session, esg_name):
    """
    This function lists all static bindings on an edge DHCP Server

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for DHCP
    :rtype: tuple
    :return: Returns a tuple with the first item being a list of tuples containing:

             [0] Binding Id
             [1] MAC Address if MAC based entry is used
             [2] VM Moid if VM based entry is used
             [3] vnic index of the attached VM if VM based entry is used
             [4] Hostname
             [5] IP Address
             [6] Default Gateway
             [7] Subnet Mask
             [8] Domain Name
             [9] Primary DNS Server
             [10] Secondary DNS Server
             [11] Lease Time
             [12] Autoconfigure DNS (true/false),

             The second item contains a list of dicts with all the pool details as returned by the NSX API
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None, None

    result = client_session.read('dhcp', uri_parameters={'edgeId': esg_id})
    if not result['body']['dhcp']['staticBindings']:
        return [], []

    bindings = client_session.normalize_list_return(result['body']['dhcp']['staticBindings']['staticBinding'])
    bindings_list = [(binding.get('bindingId'), binding.get('macAddress'), binding.get('vmId'),
                      binding.get('vnicId'), binding.get('hostname'), binding.get('ipAddress'),
                      binding.get('defaultGateway'), binding.get('subnetMask'), binding.get('domainName'),
                      binding.get('primaryNameServer'), binding.get('secondaryNameServer'),
                      binding.get('leaseTime'), binding.get('autoConfigureDNS')) for binding in bindings]

    bindings_list_verbose = [binding for binding in bindings]

    return bindings_list, bindings_list_verbose


def _list_dhcp_bindings(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    bindings, bindings_verbose = list_dhcp_bindings(client_session, kwargs['esg_name'])

    if kwargs['verbose']:
        print json.dumps(bindings_verbose)
    else:
        print tabulate(bindings, headers=["Binding ID", "MAC", "VM Id", "vnic Index", "Hostname", "IP", "Default Gw",
                                          "Subnet Mask", "Domain Name", "DNS 1", "DNS 2", "Lease Time",
                                          "Auto Config DNS"], tablefmt="psql")


def delete_dhcp_binding(client_session, esg_name, binding_id):
    """
    This function deletes a DHCP binding from an edge DHCP Server

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for DHCP
    :type binding_id: str
    :param binding_id: The Id of the binding to be deleted (e.g. binding-3)
    :rtype: bool
    :return: Returns None if Edge was not found or the operation failed, returns true on success
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    result = client_session.delete('dhcpStaticBindingID', uri_parameters={'edgeId': esg_id, 'bindingID': binding_id})

    if result['status'] == 204:
        return True
    else:
        return None


def _delete_dhcp_binding(client_session, **kwargs):
    needed_params = ['esg_name', 'binding_id']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = delete_dhcp_binding(client_session, kwargs['esg_name'], kwargs['binding_id'])

    if result:
        print 'Deleting DHCP binding {} on esg {} succeeded'.format(kwargs['binding_id'], kwargs['esg_name'])
    else:
        print 'Deleting DHCP binding {} on esg {} failed'.format(kwargs['binding_id'], kwargs['esg_name'])


def dhcp_server(client_session, esg_name, enabled=None, syslog_enabled=None, syslog_level=None):
    """
    This function enables/disables the DHCP server on an Edge Gateway and sets the logging status and Level

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for DHCP
    :type enabled: bool
    :param enabled: True/False The desired state of the DHCP Server
    :type syslog_enabled: str
    :param syslog_enabled: ('true'/'false') The desired logging state of the DHCP Server
    :type syslog_level: str
    :param syslog_level: The logging level for DHCP on this Edge (INFO/WARNING/etc.)
    :rtype: bool
    :return: Return True on success of the operation
    """
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
    """
    This function returns the configuration of the DHCP server on an Edge Gateway

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for DHCP
    :rtype: dict
    :return: A dict containing the configuration information of DHCP on the specified Edge Gateway
    """
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
    enable_server:   Enables the edge DHCP server and configures its logging status and level
    disable_server:  Disables the edge DHCP server
    read:            Retrieve the status and read the config of the edge DHCP Service on the edge
    add_pool:        Adds an DHCP Pool to the edge DHCP Server
    list_pools:      Lists all DHCP Pools configured on the edge DHCP Server
    delete_pool:     Deletes a DHCP Pool from the edge DHCP Server
    add_mac_binding: Adds a MAC based static DHCP binding to the edge DHCP Server
    add_vm_binding:  Adds a VM vnic specific static DHCP binding to the edge DHCP Server
    list_bindings:   Lists all DHCP static bindings on the edge DHCP Server
    delete_binding:  Deletes a static DHCP binding from the edge DHCP Server
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
    parser.add_argument("-pid",
                        "--pool_id",
                        help="The IP Pool Id when deleting an IP Pool")
    parser.add_argument("-bid",
                        "--binding_id",
                        help="The Binding Id when deleting an static binding")
    parser.add_argument("-ip",
                        "--ip",
                        help="The IP Address for a static DHCP Binding entry")
    parser.add_argument("-mac",
                        "--mac",
                        help="The MAC Address for a static MAC based DHCP Binding entry")
    parser.add_argument("-hn",
                        "--hostname",
                        help="The Hostname for a static DHCP Binding entry")
    parser.add_argument("-vm",
                        "--vm_name",
                        help="The Name of the VM for a static VM Based DHCP Binding entry")
    parser.add_argument("-vn",
                        "--vnic_id",
                        help="The vnic Id of the VM for a static VM Based DHCP Binding entry (e.g. 0 for vnic0)")

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
    except ConfigParser.NoSectionError:
        nsxramlfile_dir = resource_filename(__name__, 'api_spec')
        nsxramlfile = '{}/nsxvapi.raml'.format(nsxramlfile_dir)

    client_session = NsxClient(nsxramlfile, config.get('nsxv', 'nsx_manager'),
                               config.get('nsxv', 'nsx_username'), config.get('nsxv', 'nsx_password'), debug=debug)

    vccontent = connect_to_vc(config.get('vcenter', 'vcenter'), config.get('vcenter', 'vcenter_user'),
                              config.get('vcenter', 'vcenter_passwd'))
    try:
        command_selector = {
            'enable_server': _enable_server,
            'disable_server': _disable_server,
            'read': _read,
            'add_pool': _add_dhcp_pool,
            'list_pools': _list_dhcp_pools,
            'delete_pool': _delete_dhcp_pool,
            'add_mac_binding': _add_mac_binding,
            'add_vm_binding': _add_vm_binding,
            'list_bindings': _list_dhcp_bindings,
            'delete_binding': _delete_dhcp_binding,
            }
        command_selector[args.command](client_session, vccontent=vccontent, esg_name=args.esg_name,
                                       logging=args.logging, log_level=args.log_level, ip_range=args.ip_range,
                                       default_gateway=args.default_gateway, subnet_mask=args.subnet_mask,
                                       domain_name=args.domain_name, dns_server_1=args.dns_server_1,
                                       dns_server_2=args.dns_server_2, lease_time=args.lease_time,
                                       auto_dns=args.auto_dns, pool_id=args.pool_id, ip=args.ip, mac=args.mac,
                                       hostname=args.hostname, vm_name=args.vm_name, vnic_id=args.vnic_id,
                                       binding_id=args.binding_id, verbose=args.verbose)
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
