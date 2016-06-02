#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2016 VMware, Inc. All Rights Reserved.
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
from libutils import get_logical_switch, get_vdsportgroupid, connect_to_vc, check_for_parameters
from libutils import get_datacentermoid, get_edgeresourcepoolmoid, get_edge, get_datastoremoid
from tabulate import tabulate
from nsxramlclient.client import NsxClient
from argparse import RawTextHelpFormatter


def esg_create(client_session, esg_name, esg_pwd, esg_size, datacentermoid, datastoremoid, resourcepoolid, default_pg,
               esg_username=None, esg_remote_access=None):
    """
    This function creates a new Edge Services Gateway
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG to be created
    :param esg_pwd: The CLI password of the ESG
    :param esg_size: The size of the ESG, options are compact, large, quadlarge, xlarge
    :param datacentermoid: The managed object id of the vCenter DC Object to deploy the ESG in
    :param datastoremoid: The managed object id of the vCenter Datastore Object to deploy the ESG in
    :param resourcepoolid: The managed object id of the vCenter Cluster or RP Object to deploy the ESG in
    :param default_pg: The managed object id of the port group for the first vnic (on creation the first vnic must
                       be connected to a valid portgroup in NSX)
    :param esg_username: The Username for the CLI and SSH access (default: admin)
    :param esg_remote_access: Enables / Disables SSH access to the Edge Host (default: False)
    :return: returns a tuple, the first item is a string containing the Edge ID, the second is a dictionary
             containing the ESG details retrieved from the API
    """
    esg_create_dict = client_session.extract_resource_body_example('nsxEdges', 'create')

    if not esg_username:
        esg_username = 'admin'
    if not esg_remote_access:
        esg_remote_access = 'false'

    first_vnic = {'index': '0', 'portgroupId': default_pg, 'isConnected': 'True'}

    del esg_create_dict['edge']['vnics']['vnic']
    del esg_create_dict['edge']['appliances']['appliance']['hostId']
    del esg_create_dict['edge']['appliances']['appliance']['customField']

    esg_create_dict['edge']['vnics'] = {'vnic': first_vnic}

    esg_create_dict['edge']['name'] = esg_name
    esg_create_dict['edge']['cliSettings'] = {'password': esg_pwd, 'remoteAccess': esg_remote_access,
                                              'userName': esg_username}
    esg_create_dict['edge']['appliances']['applianceSize'] = esg_size
    esg_create_dict['edge']['datacenterMoid'] = datacentermoid
    esg_create_dict['edge']['appliances']['appliance']['datastoreId'] = datastoremoid
    esg_create_dict['edge']['appliances']['appliance']['resourcePoolId'] = resourcepoolid

    new_esg = client_session.create('nsxEdges', request_body_dict=esg_create_dict)
    if new_esg['status'] == 201:
        return new_esg['objectId'], new_esg['body']
    else:
        return None, None


def _esg_create(client_session, vccontent, **kwargs):
    needed_params = ['esg_name', 'esg_size', 'esg_pwd', 'datacenter_name', 'edge_datastore', 'edge_cluster',
                     'portgroup']
    if not check_for_parameters(needed_params, kwargs):
        return None
    datacentermoid = get_datacentermoid(vccontent, kwargs['datacenter_name'])
    datastoremoid = get_datastoremoid(vccontent, kwargs['datacenter_name'], kwargs['edge_datastore'])
    resourcepoolid = get_edgeresourcepoolmoid(vccontent, kwargs['datacenter_name'], kwargs['edge_cluster'])
    portgroupmoid = get_vdsportgroupid(vccontent, kwargs['datacenter_name'], kwargs['portgroup'])

    esg_id, esg_params = esg_create(client_session, kwargs['esg_name'], kwargs['esg_pwd'], kwargs['esg_size'],
                                    datacentermoid, datastoremoid, resourcepoolid, portgroupmoid,
                                    esg_remote_access=kwargs['esg_remote_access'])
    if kwargs['verbose'] and esg_id:
        edge_id, esg_details = esg_read(client_session, esg_id)
        print json.dumps(esg_details)
    elif esg_id:
        print 'Edge Service Gateway {} created with the ID {}'.format(kwargs['esg_name'], esg_id)
    else:
        print 'Edge Service Gateway {} creation failed'.format(kwargs['esg_name'])


def esg_delete(client_session, esg_name):
    """
    This function will delete a esg in NSX
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG to delete
    :return: returns a tuple, the first item is a boolean indicating success or failure to delete the ESG,
             the second item is a string containing to ESG id of the deleted ESG
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return False, None
    client_session.delete('nsxEdge', uri_parameters={'edgeId': esg_id})
    return True, esg_id


def _esg_delete(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None
    esg_name = kwargs['esg_name']
    result, dlr_id = esg_delete(client_session, esg_name)
    if result and kwargs['verbose']:
        return json.dumps(dlr_id)
    elif result:
        print 'Edge Services Router {} with the ID {} has been deleted'.format(esg_name, dlr_id)
    else:
        print 'Edge Services Router deletion failed'


def esg_read(client_session, esg_name):
    """
    This funtions retrieves details of a ESG in NSX
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the esg to retrieve details from
    :return: returns a tuple, the first item is a string containing the ESG ID, the second is a dictionary
             containing the ESG details retrieved from the API
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None, None
    read_result = client_session.read('nsxEdge', uri_parameters={'edgeId': esg_id})
    esg_params = read_result['body']
    return esg_id, esg_params


def _esg_read(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None
    esg_id, esg_params = esg_read(client_session, kwargs['esg_name'])
    if esg_params and kwargs['verbose']:
        print json.dumps(esg_params)
    elif esg_id:
        print 'Edge Services Gateway {} has the ID {}'.format(kwargs['esg_name'], esg_id)
    else:
        print 'Edge Services Gateway {} not found'.format(kwargs['esg_name'])


def esg_list(client_session):
    """
    This function returns all DLR found in NSX
    :param client_session: An instance of an NsxClient Session
    :return: returns a tuple, the first item is a list of tuples with item 0 containing the DLR Name as string
             and item 1 containing the dlr id as string. The second item contains a list of dictionaries containing
             all DLR details
    """
    all_edges = client_session.read_all_pages('nsxEdges', 'read')
    esg_lst = []
    esg_list_verbose = []
    for edge in all_edges:
        if edge['edgeType'] == "gatewayServices":
            esg_lst.append((edge['name'], edge['objectId']))
            esg_list_verbose.append(edge)
    return esg_lst, esg_list_verbose


def _esg_list_print(client_session, **kwargs):
    esg_list_result, esg_params = esg_list(client_session)
    if kwargs['verbose']:
        print esg_params
    else:
        print tabulate(esg_list_result, headers=["ESG name", "ESG ID"], tablefmt="psql")


def esg_cfg_interface(client_session, esg_name, ifindex, ipaddr=None, netmask=None, prefixlen=None, name=None, mtu=None,
                      is_connected=None, portgroup_id=None, vnic_type=None, enable_send_redirects=None,
                      enable_proxy_arp=None):
    """
    This function configures vnic interfaces on ESGs
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG to configure interfaces on
    :param ifindex: The vnic index, e.g. vnic3 and the index 3
    :param ipaddr: (Optional) The primary IP Address to be configured for this interface
    :param netmask: (Optional) The netmask in the x.x.x.x format
    :param prefixlen: (Optional) The prefix length, this takes precedence over the netmask
    :param name: (Optional) The name assigned to the vnic
    :param mtu: (Optional) The vnic MTU
    :param is_connected: (Optional) The vnic connection state (true/false)
    :param portgroup_id: (Optional) The portgroup id of logical switch id to connenct this vnic to
    :param vnic_type: (Optional) The vnic type (uplink/internal)
    :param enable_send_redirects: (Optional) Whether the interface will send icmp redirects (true/false)
    :param enable_proxy_arp: (Optional) Whether the interface will do proxy arp (true/false)
    :return: Returns True on successful configuration of the Interface
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return False
    vnic_config = client_session.read('vnic', uri_parameters={'index': ifindex, 'edgeId': esg_id})['body']

    if not mtu:
        mtu = 1500
    if not vnic_type:
        vnic_type = 'internal'

    vnic_config['vnic']['mtu'] = mtu
    vnic_config['vnic']['type'] = vnic_type
    if name:
        vnic_config['vnic']['name'] = name
    if portgroup_id:
        vnic_config['vnic']['portgroupId'] = portgroup_id
    if enable_send_redirects:
        vnic_config['vnic']['enableSendRedirects'] = enable_send_redirects
    if enable_proxy_arp:
        vnic_config['vnic']['enableProxyArp'] = enable_proxy_arp
    if is_connected:
        vnic_config['vnic']['isConnected'] = is_connected
    if ipaddr and (netmask or prefixlen):
        address_group = {}
        if netmask:
            address_group['subnetMask'] = netmask
        if prefixlen:
            address_group['subnetPrefixLength'] = str(prefixlen)
        address_group['primaryAddress'] = ipaddr
        vnic_config['vnic']['addressGroups'] = {'addressGroup': address_group}

    cfg_result = client_session.update('vnic', uri_parameters={'index': ifindex, 'edgeId': esg_id},
                                       request_body_dict=vnic_config)
    if cfg_result['status'] == 204:
        return True
    else:
        return False


def _esg_cfg_interface(client_session, vccontent, **kwargs):
    needed_params = ['vnic_index', 'esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    if kwargs['logical_switch'] and kwargs['portgroup']:
        print 'Both a logical switch and a portgroup were specified, please only specify one of these values'
        return None

    if kwargs['logical_switch']:
        lsid, lsparams = get_logical_switch(client_session, kwargs['logical_switch'])
        portgroup = lsid
    elif kwargs['portgroup']:
        pgid = get_vdsportgroupid(vccontent, kwargs['datacenter_name'], kwargs['portgroup'])
        portgroup = pgid
    else:
        portgroup = None

    if kwargs['vnic_ip']:
        if not kwargs['vnic_mask']:
            print 'You need to specify a netmask when configuring an IP Address on the Interface'
            return None
        try:
            pflen_int = int(kwargs['vnic_mask'])
            prefixlen = pflen_int
            netmask = None
        except ValueError:
            netmask = kwargs['vnic_mask']
            prefixlen = None
    else:
        netmask = None
        prefixlen = None

    result = esg_cfg_interface(client_session, kwargs['esg_name'], kwargs['vnic_index'], name=kwargs['vnic_name'],
                               vnic_type=kwargs['vnic_type'], portgroup_id=portgroup, is_connected=kwargs['vnic_state'],
                               ipaddr=kwargs['vnic_ip'], netmask=netmask,
                               prefixlen=prefixlen)
    if result:
        print 'Edge Services Router {} vnic{} has been configured'.format(kwargs['esg_name'], kwargs['vnic_index'])
    else:
        print 'Edge Services Router {} vnic{} configuration failed'.format(kwargs['esg_name'], kwargs['vnic_index'])


def esg_clear_interface(client_session, esg_name, ifindex):
    """
    This function resets the vnic configuration of an ESG to its default state
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG to configure interfaces on
    :param ifindex: The vnic index, e.g. vnic3 and the index 3
    :return: Returns True on successful configuration of the Interface
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return False
    vnic_config = client_session.read('vnic', uri_parameters={'index': ifindex, 'edgeId': esg_id})['body']

    vnic_config['vnic']['mtu'] = '1500'
    vnic_config['vnic']['type'] = 'internal'
    vnic_config['vnic']['name'] = 'vnic{}'.format(ifindex)
    vnic_config['vnic']['addressGroups'] = None
    vnic_config['vnic']['portgroupId'] = None
    vnic_config['vnic']['portgroupName'] = None
    vnic_config['vnic']['enableProxyArp'] = 'false'
    vnic_config['vnic']['enableSendRedirects'] = 'false'
    vnic_config['vnic']['isConnected'] = 'false'

    cfg_result = client_session.update('vnic', uri_parameters={'index': ifindex, 'edgeId': esg_id},
                                       request_body_dict=vnic_config)
    if cfg_result['status'] == 204:
        return True
    else:
        return False


def _esg_clear_interface(client_session, **kwargs):
    needed_params = ['vnic_index', 'esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = esg_clear_interface(client_session, kwargs['esg_name'], kwargs['vnic_index'])

    if result:
        print 'Edge Services Router {} vnic{} configuration has been cleared'.format(kwargs['esg_name'],
                                                                                     kwargs['vnic_index'])
    else:
        print 'Edge Services Router {} vnic{} configuration failed'.format(kwargs['esg_name'], kwargs['vnic_index'])


def esg_list_interfaces(client_session, esg_name):
    """
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG to list interfaces of
    :return: returns a list of tuples with
             item 0 containing the vnic Name as string,
             item 1 containing the vnic index as string,
             item 2 containing the ip as string,
             item 3 containing the netmask as string,
             item 4 containing the 'connected-to' portgroup as string,
             The second item contains a list of dictionaries containing all ESG vnic details
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None, None
    all_int_response = client_session.read('vnics', uri_parameters={'edgeId': esg_id})
    all_int = client_session.normalize_list_return(all_int_response['body']['vnics']['vnic'])
    esg_int_list = []
    esg_int_list_verbose = []
    for interface in all_int:
        try:
            ip = interface['addressGroups']['addressGroup']['primaryAddress']
            snmask = interface['addressGroups']['addressGroup']['subnetMask']
        except TypeError:
            ip = ''
            snmask = ''
        try:
            pgname = interface['portgroupName']
        except KeyError:
            pgname = ''

        esg_int_list.append((interface['name'], interface['index'], ip, snmask, pgname))
        esg_int_list_verbose.append(interface)
    return esg_int_list, esg_int_list_verbose


def _esg_list_interfaces(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    esg_int_list, esg_int_list_verbose = esg_list_interfaces(client_session, kwargs['esg_name'])
    if esg_int_list_verbose and kwargs['verbose']:
        print json.dumps(esg_int_list_verbose)
    elif esg_int_list:
        print tabulate(esg_int_list, headers=["Vnic name", "Vnic ID", "Vnic IP", "Vnic subnet", "Connected To"],
                       tablefmt="psql")
    else:
        print 'Failed to get interface list of Edge {}'.format(kwargs['esg_name'])


def esg_dgw_set(client_session, esg_name, dgw_ip, vnic, mtu=None, admin_distance=None):
    """
    This function sets the default gateway on an ESG
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG to list interfaces of
    :param dgw_ip: The default gateway ip (next hop)
    :param vnic: (Optional) The vnic index of were the default gateway is reachable on
    :param mtu: (Optional) The MTU of the defautl gateway (default=1500)
    :param admin_distance: (OIptional) Admin distance of the defautl route (default=1)
    :return: True on success, False on failure
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return False
    if not mtu:
        mtu = '1500'
    if not admin_distance:
        admin_distance = '1'

    rtg_cfg = client_session.read('routingConfigStatic', uri_parameters={'edgeId': esg_id})['body']
    rtg_cfg['staticRouting']['defaultRoute'] = {'vnic': vnic, 'gatewayAddress': dgw_ip,
                                                'adminDistance': admin_distance, 'mtu': mtu}

    cfg_result = client_session.update('routingConfigStatic', uri_parameters={'edgeId': esg_id},
                                       request_body_dict=rtg_cfg)
    if cfg_result['status'] == 204:
        return True
    else:
        return False


def _esg_dgw_set(client_session, **kwargs):
    needed_params = ['esg_name', 'next_hop']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = esg_dgw_set(client_session, kwargs['esg_name'], kwargs['next_hop'], kwargs['vnic_index'])

    if result:
        print 'Edge Services Router {} default gateway config succeeded'.format(kwargs['esg_name'])
    else:
        print 'Edge Services Router {} default gateway config failed'.format(kwargs['esg_name'])


def esg_dgw_clear(client_session, esg_name):
    """
    This function clears the default gateway config on an ESG
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG to list interfaces of
    :return: True on success, False on failure
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return False

    rtg_cfg = client_session.read('routingConfigStatic', uri_parameters={'edgeId': esg_id})['body']
    rtg_cfg['staticRouting']['defaultRoute'] = None

    cfg_result = client_session.update('routingConfigStatic', uri_parameters={'edgeId': esg_id},
                                       request_body_dict=rtg_cfg)
    if cfg_result['status'] == 204:
        return True
    else:
        return False


def _esg_dgw_clear(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = esg_dgw_clear(client_session, kwargs['esg_name'])

    if result:
        print 'Edge Services Router {} default gateway cleared'.format(kwargs['esg_name'])
    else:
        print 'Edge Services Router {} clearing the default gateway config failed'.format(kwargs['esg_name'])


def esg_dgw_read(client_session, esg_name):
    """
    This function return the default gateway configuration
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG to return the default gateway configuration from
    :return: returns a tuple, the firt item of the tuple contains a list of 1 tuple with
             item 0 containing the vnic used by the default route as string,
             item 1 containing the gateway IP as string,
             item 2 containing the admin distance of the default route as string,
             item 3 containing the mtu of the gateway as string
             The second item in the tuple contains a dict with all the default gateway config details
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return False

    rtg_cfg = client_session.read('routingConfigStatic', uri_parameters={'edgeId': esg_id})['body']

    if 'defaultRoute' not in rtg_cfg['staticRouting'].keys():
        return [()], {}

    mtu = rtg_cfg['staticRouting']['defaultRoute']['mtu']

    try:
        admin_distance = rtg_cfg['staticRouting']['defaultRoute']['adminDistance']
    except KeyError:
        admin_distance = '1'
    try:
        vnic = rtg_cfg['staticRouting']['defaultRoute']['vnic']
    except KeyError:
        vnic = ''

    dgw_cfg_tpl = [(vnic, rtg_cfg['staticRouting']['defaultRoute']['gatewayAddress'], admin_distance, mtu)]

    return dgw_cfg_tpl, rtg_cfg['staticRouting']['defaultRoute']


def _esg_dgw_read(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    dgw_cfg_tpl, rtg_cfg = esg_dgw_read(client_session, kwargs['esg_name'])

    if rtg_cfg and kwargs['verbose']:
        print json.dumps(rtg_cfg)
    elif dgw_cfg_tpl:
        print tabulate(dgw_cfg_tpl, headers=["vNic", "Gateway IP", "Admin Distance", "MTU"], tablefmt="psql")
    else:
        print 'Failed to get default gateway info of Edge {}'.format(kwargs['esg_name'])


def esg_route_add(client_session, esg_name, network, next_hop, vnic, mtu=None, admin_distance=None, description=None):
    """
    This function adds a static route to an ESG
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG where the route should be added
    :param network: The routes network in the x.x.x.x/yy format, e.g. 192.168.1.0/24
    :param next_hop: The next hop ip
    :param vnic: (Optional) The vnic index of were this route is reachable on
    :param mtu: (Optional) The MTU of the route (default=1500)
    :param admin_distance: (Optional) Admin distance of the defautl route (default=1)
    :param description: (Optional) A description for this route
    :return: True on success, False on failure
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return False
    if not mtu:
        mtu = '1500'
    if not admin_distance:
        admin_distance = '1'

    rtg_cfg = client_session.read('routingConfigStatic', uri_parameters={'edgeId': esg_id})['body']
    if rtg_cfg['staticRouting']['staticRoutes']:
        routes = client_session.normalize_list_return(rtg_cfg['staticRouting']['staticRoutes']['route'])
    else:
        routes = []
    new_route = {'vnic': vnic, 'network': network, 'nextHop': next_hop, 'adminDistance': admin_distance,
                 'mtu': mtu, 'description': description}
    routes.append(new_route)
    rtg_cfg['staticRouting']['staticRoutes'] = {'route': routes}

    cfg_result = client_session.update('routingConfigStatic', uri_parameters={'edgeId': esg_id},
                                       request_body_dict=rtg_cfg)
    if cfg_result['status'] == 204:
        return True
    else:
        return False


def _esg_route_add(client_session, **kwargs):
    needed_params = ['esg_name', 'next_hop', 'route_net']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = esg_route_add(client_session, kwargs['esg_name'], kwargs['route_net'], kwargs['next_hop'],
                           kwargs['vnic_index'])

    if result:
        print 'Added route {} to Edge Services Router {}'.format(kwargs['route_net'], kwargs['esg_name'])
    else:
        print 'Addition of route {} to Edge Services Router {} failed'.format(kwargs['route_net'], kwargs['esg_name'])


def esg_route_del(client_session, esg_name, network, next_hop):
    """
    This function deletes a static route to an ESG
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG where the route should be deleted
    :param network: The routes network in the x.x.x.x/yy format, e.g. 192.168.1.0/24
    :param next_hop: The next hop ip
    :return: True on success, False on failure
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return False

    rtg_cfg = client_session.read('routingConfigStatic', uri_parameters={'edgeId': esg_id})['body']
    if rtg_cfg['staticRouting']['staticRoutes']:
        routes = client_session.normalize_list_return(rtg_cfg['staticRouting']['staticRoutes']['route'])
    else:
        return False

    routes_filtered = [route for route in routes if not (route['network'] == network and route['nextHop'] == next_hop)]
    if len(routes_filtered) == len(routes):
        return False
    rtg_cfg['staticRouting']['staticRoutes'] = {'route': routes_filtered}

    cfg_result = client_session.update('routingConfigStatic', uri_parameters={'edgeId': esg_id},
                                       request_body_dict=rtg_cfg)
    if cfg_result['status'] == 204:
        return True
    else:
        return False


def _esg_route_del(client_session, **kwargs):
    needed_params = ['esg_name', 'next_hop', 'route_net']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = esg_route_del(client_session, kwargs['esg_name'], kwargs['route_net'], kwargs['next_hop'])

    if result:
        print 'Deletion of route {} on Edge Services Router {} succeeded'.format(kwargs['route_net'],
                                                                                 kwargs['esg_name'])
    else:
        print 'Deletion of route {} on Edge Services Router {} failed'.format(kwargs['route_net'], kwargs['esg_name'])


def esg_route_list(client_session, esg_name):
    """
    This function return the configured static routes
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG of which the routes should be listed
    :return: returns a tuple, the firt item of the tuple contains a list of 1 tuple with
             item 0 containing the routes network,
             item 1 containing the next hop IP as string,
             item 2 containing the vnic used by the route as string,
             item 3 containing the admin distance of the route as string,
             item 4 containing the mtu of the route as string
             The second item in the tuple contains a dict with all the static routing config details
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return False

    rtg_cfg = client_session.read('routingConfigStatic', uri_parameters={'edgeId': esg_id})['body']

    if not rtg_cfg['staticRouting']['staticRoutes']:
        return [()], {}

    routes = []
    routes_api = client_session.normalize_list_return(rtg_cfg['staticRouting']['staticRoutes']['route'])
    for route in routes_api:
        if 'vnic' in route.keys():
            vnic = route['vnic']
        else:
            vnic = ''
        add_route = (route['network'], route['nextHop'], vnic, route['adminDistance'], route['mtu'])
        routes.append(add_route)

    return routes, rtg_cfg['staticRouting']['staticRoutes']


def _esg_route_list(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    routes, rtg_cfg = esg_route_list(client_session, kwargs['esg_name'])

    if rtg_cfg and kwargs['verbose']:
        print json.dumps(rtg_cfg)
    elif routes:
        print tabulate(routes, headers=["network", "next-hop", "vnic", "admin distance", "mtu"], tablefmt="psql")
    else:
        print 'Failed to get static roues of Edge {}'.format(kwargs['esg_name'])


def esg_fw_default_set(client_session, esg_name, def_action, logging_enabled=None):
    """
    This function sets the default firewall rule to accept or deny
    :param client_session: An instance of an NsxClient Session
    :param esg_name: The name of the ESG to which you want to apply the default firewall rule:
    :param def_action: Default firewall action, values are either accept or deny
    :param logging_enabled: (Optional) Is logging enabled by default (true/false)
    :return: True on success, False on failure
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return False

    if not logging_enabled:
        logging_enabled = 'false'

    def_policy_body = client_session.extract_resource_body_example('defaultFirewallPolicy', 'update')
    def_policy_body['firewallDefaultPolicy']['action'] = def_action
    def_policy_body['firewallDefaultPolicy']['loggingEnabled'] = logging_enabled

    cfg_result = client_session.update('defaultFirewallPolicy', uri_parameters={'edgeId': esg_id},
                                  request_body_dict=def_policy_body)

    if cfg_result['status'] == 204:
        return True
    else:
        return False


def _esg_fw_default_set(client_session, **kwargs):
    needed_params = ['esg_name', 'fw_default']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = esg_fw_default_set(client_session, kwargs['esg_name'], kwargs['fw_default'])

    if result:
        print 'Default firewall policy on Edge Services Router {} set to {}'.format(kwargs['esg_name'],
                                                                                 kwargs['fw_default'])
    else:
        print 'Setting default firewall policy on Edge Services Router {} failed'.format(kwargs['esg_name'])


def contruct_parser(subparsers):
    parser = subparsers.add_parser('esg', description="nsxv function for edge services gateway'%(prog)s @params.conf'.",
                                   help="Functions for edge services gateways",
                                   formatter_class=RawTextHelpFormatter)
    parser.add_argument("command", help="""
    create:           create a new ESG
    read:             return the id of a ESG
    delete:           delete an ESG
    list:             return a list of all ESG
    set_dgw:          set ESG default gateway ip address
    del_dgw:          delete ESG default gateway ip address
    read_dgw:         show the configured default gateway
    add_route:        Add a static route to an ESG
    del_route:        Delete a static route from an ESG
    list_routes:      List all configured static routes on an ESG
    cfg_interface:    Configure IP and other interface details
    clear_interface:  remove all configuration from an interface
    list_interfaces:  list all interfaces of dlr
    set_size:         Resize ESG
    set_fw_status:    Set the default firewall policy to accept or deny
    """)

    parser.add_argument("-n",
                        "--esg_name",
                        help="ESG name")
    parser.add_argument("-p",
                        "--esg_password",
                        help="ESG admin password, default is 'VMware1!VMware1!'",
                        default="VMware1!VMware1!")
    parser.add_argument("-s",
                        "--esg_size",
                        help="ESG size (compact, large, quadlarge, xlarge), default is compact",
                        default="compact")
    parser.add_argument("-r",
                        "--esg_remote_access",
                        help="ESG state of remote access (SSH) (True = enabled, False = disabled), default is False",
                        default="false")
    parser.add_argument("-pg",
                        "--portgroup",
                        help="ESG portgroup name for vnic related operations and for the first vnic pg of esg creation")
    parser.add_argument("-ls",
                        "--logical_switch",
                        help="ESG logical switch for vnic related operations and for the first vnic of esg creation")
    parser.add_argument("-vi",
                        "--vnic_index",
                        help="vnic Id when configuring Vnic interfaces (0 to 9)")
    parser.add_argument("-vt",
                        "--vnic_type",
                        help="vnic type when configuring Vnic interfaces (internal or uplink)")
    parser.add_argument("-vn",
                        "--vnic_name",
                        help="vnic name when configuring Vnic interfaces (internal or uplink)")
    parser.add_argument("-vs",
                        "--vnic_state",
                        help="vnic connection state (true/false) Default is true",
                        default='true')
    parser.add_argument("-ip",
                        "--vnic_ip",
                        help="vnic IP Address")
    parser.add_argument("-m",
                        "--vnic_mask",
                        help="vnic subnet mask or size (e.g. 255.255.255.0 or 24)")
    parser.add_argument("-gw",
                        "--next_hop",
                        help="ESG default gateway or static route next hop")
    parser.add_argument("-rt",
                        "--route_net",
                        help="Network the static route points to in the x.x.x.x/yy format, e.g. 192.168.1.0/24")
    parser.add_argument("-fw",
                        "--fw_default",
                        help="ESG firewall default rule action (accept/deny)")
    parser.add_argument("-dc",
                        "--datacenter_name",
                        help="vCenter DC name to deploy ESGs in, default is taken from INI File")
    parser.add_argument("-ds",
                        "--edge_datastore",
                        help="Datastore name to deploy ESGs in, default is taken from INI File")
    parser.add_argument("-cl",
                        "--edge_cluster",
                        help="vCenter Cluster or Ressource Pool to deploy ESGs in, default is taken from INI File")

    parser.set_defaults(func=_esg_main)


def _esg_main(args):
    if args.debug:
        debug = True
    else:
        debug = False

    config = ConfigParser.ConfigParser()
    assert config.read(args.ini), 'could not read config file {}'.format(args.ini)

    client_session = NsxClient(config.get('nsxraml', 'nsxraml_file'), config.get('nsxv', 'nsx_manager'),
                               config.get('nsxv', 'nsx_username'), config.get('nsxv', 'nsx_password'), debug=debug)

    vccontent = connect_to_vc(config.get('vcenter', 'vcenter'), config.get('vcenter', 'vcenter_user'),
                              config.get('vcenter', 'vcenter_passwd'))

    if args.datacenter_name:
        datacenter_name = args.datacenter_name
    else:
        datacenter_name = config.get('defaults', 'datacenter_name')

    if args.edge_datastore:
        edge_datastore = args.edge_datastore
    else:
        edge_datastore = config.get('defaults', 'edge_datastore')

    if args.edge_cluster:
        edge_cluster = args.edge_cluster
    else:
        edge_cluster = config.get('defaults', 'edge_cluster')

    try:
        command_selector = {
            'list': _esg_list_print,
            'create': _esg_create,
            'delete': _esg_delete,
            'read': _esg_read,
            'set_dgw': _esg_dgw_set,
            'clear_dgw': _esg_dgw_clear,
            'read_dgw':  _esg_dgw_read,
            'cfg_interface': _esg_cfg_interface,
            'clear_interface': _esg_clear_interface,
            'list_interfaces': _esg_list_interfaces,
            'set_fw_status': _esg_fw_default_set,
            'add_route': _esg_route_add,
            'del_route': _esg_route_del,
            'list_routes': _esg_route_list
        }
        command_selector[args.command](client_session, vccontent=vccontent, esg_name=args.esg_name,
                                       esg_pwd=args.esg_password, esg_size=args.esg_size,
                                       datacenter_name=datacenter_name, edge_datastore=edge_datastore,
                                       edge_cluster=edge_cluster, next_hop=args.next_hop,
                                       portgroup=args.portgroup, logical_switch=args.logical_switch,
                                       vnic_index=args.vnic_index, vnic_type=args.vnic_type, vnic_name=args.vnic_name,
                                       vnic_state=args.vnic_state, vnic_ip=args.vnic_ip, vnic_mask=args.vnic_mask,
                                       route_net=args.route_net, fw_default=args.fw_default,
                                       esg_remote_access=args.esg_remote_access, verbose=args.verbose)
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
