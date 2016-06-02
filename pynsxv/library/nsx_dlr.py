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

__author__ = 'Dimitri Desmidt'

import argparse
import ConfigParser
import json
from libutils import get_logical_switch, get_vdsportgroupid, connect_to_vc
from libutils import get_datacentermoid, get_edgeresourcepoolmoid, get_edge, get_datastoremoid
from tabulate import tabulate
from nsxramlclient.client import NsxClient
from argparse import RawTextHelpFormatter


def dlr_add_interface(client_session, dlr_id, interface_ls_id, interface_ip, interface_subnet):
    """
    This function adds an interface gw to one dlr
    :param dlr_id: dlr uuid
    :param interface_ls_id: new interface logical switch
    :param interface_ip: new interface ip address
    :param interface_subnet: new interface subnet
    """

    # get a template dict for the dlr interface
    dlr_interface_dict = client_session.extract_resource_body_example('interfaces', 'create')

    # add default gateway to the created dlr if dgw entered
    dlr_interface_dict['interfaces']['interface']['addressGroups']['addressGroup']['primaryAddress'] = interface_ip
    dlr_interface_dict['interfaces']['interface']['addressGroups']['addressGroup']['subnetMask'] = interface_subnet
    dlr_interface_dict['interfaces']['interface']['isConnected'] = "True"
    dlr_interface_dict['interfaces']['interface']['connectedToId'] = interface_ls_id

    dlr_interface = client_session.create('interfaces', uri_parameters={'edgeId': dlr_id},
                                          query_parameters_dict={'action': "patch"},
                                          request_body_dict=dlr_interface_dict)
    return dlr_interface


def _dlr_add_interface(client_session, datacenter_name, vccontent, **kwargs):
    if not (kwargs['dlr_name'] and kwargs['interface_ls_name'] and kwargs['interface_ip']
            and kwargs['interface_subnet']):
        print ('Mandatory parameters missing, [-n NAME] [--interface_ls INTERFACE_LS] [--interface_ip INTERFACE_IP] '
               '[--interface_subnet INTERFACE_SUBNET]')
        return None
    dlr_name = kwargs['dlr_name']
    interface_ls_name = kwargs['interface_ls_name']
    interface_ip = kwargs['interface_ip']
    interface_subnet = kwargs['interface_subnet']

    dlr_id, dlr_params = dlr_read(client_session, dlr_name)
    if dlr_id:
        # find interface_ls_id in vDS port groups or NSX logical switches
        interface_ls_id = get_vdsportgroupid(vccontent, datacenter_name, interface_ls_name)
        if not interface_ls_id:
            interface_ls_id, interface_ls_params = get_logical_switch(client_session, interface_ls_name)
            if not interface_ls_id:
                print 'ERROR: DLR interface logical switch {} does NOT exist as VDS port ' \
                      'group nor NSX logical switch'.format(interface_ls_name)
                return None

        dlr_add_int = dlr_add_interface(client_session, dlr_id, interface_ls_id, interface_ip, interface_subnet)
        if dlr_add_int and kwargs['verbose']:
            print json.dumps(dlr_add_int)
        else:
            print 'Interface {} added to dlr_name {} / dlr_id {}'.format(interface_ls_name, dlr_name, dlr_id)


def dlr_del_interface(client_session, dlr_id, interface_id):
    """
    This function deletes an interface gw to one dlr
    :param dlr_id: dlr uuid
    :param interface_id: dlr interface id
    """

    dlr_del_int = client_session.delete('interfaces', uri_parameters={'edgeId': dlr_id},
                                        query_parameters_dict={'index': interface_id})
    return dlr_del_int


def _dlr_del_interface(client_session, **kwargs):
    if not (kwargs['dlr_name'] and kwargs['interface_ls_name']):
        print ('Mandatory parameters missing, [-n NAME] [--interface_ls INTERFACE_LS]')
        return None
    dlr_name = kwargs['dlr_name']
    interface_ls_name = kwargs['interface_ls_name']

    dlr_id, dlr_params = dlr_read(client_session, dlr_name)

    interface_id = ""
    if dlr_id:
        # find interface_id for interface_ls_name
        all_int = client_session.read('interfaces', uri_parameters={'edgeId': dlr_id})
        for interface in all_int['body']['interfaces']['interface']:
            if interface['connectedToName'] == interface_ls_name:
                interface_id = interface['index']
        if interface_id == "":
            print 'ERROR: DLR interface logical switch {} does NOT exist DLR {}'.format(interface_ls_name, dlr_name)
        else:
            dlr_del_interface(client_session, dlr_id, interface_id)
            print 'DLR interface logical switch {} deleted on DLR {}'.format(interface_ls_name, dlr_name)


def dlr_list_interfaces(client_session, dlr_id):
    """
    This function lists all interfaces of one dlr
    :param dlr_id: dlr uuid
    """

    all_int_response = client_session.read('interfaces', uri_parameters={'edgeId': dlr_id})
    all_int = client_session.normalize_list_return(all_int_response['body']['interfaces']['interface'])
    dlr_int_list = []
    dlr_int_list_verbose = []
    for interface in all_int:
        dlr_int_list.append((interface['connectedToName'], interface['index'],
                             interface['addressGroups']['addressGroup']['primaryAddress'],
                             interface['addressGroups']['addressGroup']['subnetMask']))
        dlr_int_list_verbose.append(interface)
    return dlr_int_list, dlr_int_list_verbose


def _dlr_list_interfaces(client_session, **kwargs):
    if not kwargs['dlr_name']:
        print ('Mandatory parameter missing, [-n NAME]')
        return None
    dlr_name = kwargs['dlr_name']

    dlr_id, dlr_params = dlr_read(client_session, dlr_name)
    if dlr_id:
        dlr_int_list, dlr_int_list_verbose = dlr_list_interfaces(client_session, dlr_id)
        if kwargs['verbose']:
            print dlr_int_list_verbose
        else:
            print tabulate(dlr_int_list, headers=["Interface name", "Interface ID", "Interface IP",
                                                  "Interface subnet"], tablefmt="psql")


def dlr_create(client_session, dlr_name, dlr_pwd, dlr_size,
               datacentermoid, datastoremoid, resourcepoolid,
               ha_ls_id, uplink_ls_id, uplink_ip, uplink_subnet, uplink_dgw):
    """
    This function will create a new dlr in NSX
    :param client_session: An instance of an NsxClient Session
    :param dlr_name: The name that will be assigned to the new dlr
    :param dlr_pwd: The admin password of new dlr
    :param dlr_size: The DLR Control VM size
    :param datacentermoid: The vCenter DataCenter ID where dlr control vm will be deployed
    :param datastoremoid: The vCenter datastore ID where dlr control vm will be deployed
    :param resourcepoolid: The vCenter Cluster where dlr control vm will be deployed
    :param ha_ls_id: New dlr ha logical switch id or vds port group
    :param uplink_ls_id: New dlr uplink logical switch id or vds port group
    :param uplink_ip: New dlr uplink ip@
    :param uplink_subnet: New dlr uplink subnet
    :param uplink_dgw: New dlr default gateway
    :return: returns a tuple, the first item is the dlr ID in NSX as string, the second is string
             containing the dlr URL location as returned from the API
    """

    # get a template dict for the dlr create
    dlr_create_dict = client_session.extract_resource_body_example('nsxEdges', 'create')

    # fill the details for the new dlr in the body dict
    dlr_create_dict['edge']['type'] = "distributedRouter"
    dlr_create_dict['edge']['name'] = dlr_name
    dlr_create_dict['edge']['cliSettings'] = {'password': dlr_pwd, 'remoteAccess': "True",
                                              'userName': "admin"}
    dlr_create_dict['edge']['appliances']['applianceSize'] = dlr_size
    dlr_create_dict['edge']['datacenterMoid'] = datacentermoid
    dlr_create_dict['edge']['appliances']['appliance']['datastoreId'] = datastoremoid
    dlr_create_dict['edge']['appliances']['appliance']['resourcePoolId'] = resourcepoolid
    dlr_create_dict['edge']['mgmtInterface'] = {'connectedToId': ha_ls_id}
    dlr_create_dict['edge']['interfaces'] = {'interface': {'type': "uplink", 'isConnected': "True",
                                                           'connectedToId': uplink_ls_id,
                                                           'addressGroups': {
                                                               'addressGroup': {'primaryAddress': uplink_ip,
                                                                                'subnetMask': uplink_subnet}}}}
    del dlr_create_dict['edge']['vnics']
    del dlr_create_dict['edge']['appliances']['appliance']['hostId']
    del dlr_create_dict['edge']['appliances']['appliance']['customField']

    new_dlr = client_session.create('nsxEdges', request_body_dict=dlr_create_dict)

    # add default gateway to the created dlr if dgw entered
    if uplink_dgw:
        dlr_set_dgw(client_session, new_dlr['objectId'], uplink_dgw)

    return new_dlr['objectId'], new_dlr['location']


def _dlr_create(client_session, vccontent, datacenter_name, edge_datastore, edge_cluster, **kwargs):
    if not (kwargs['dlr_name'] and kwargs['dlr_pwd'] and kwargs['dlr_size'] and datacenter_name
            and kwargs['ha_ls_name'] and kwargs['uplink_ls_name'] and kwargs['uplink_ip'] and kwargs['uplink_subnet']
            and edge_datastore and edge_cluster):
        print ('You are missing a mandatory parameter, those are [-n NAME] [-p DLRPASSWORD] [-s DLRSIZE] '
               '[--ha_ls HA_LS] [--uplink_ls UPLINK_LS] [--uplink_ip UPLINK_IP] [--uplink_subnet UPLINK_SUBNET] '
               'and the ini file options datacenter_name,edge_datastore and edge_cluster')
        return None
    dlr_name = kwargs['dlr_name']
    dlr_pwd = kwargs['dlr_pwd']
    dlr_size = kwargs['dlr_size']

    datacentermoid = get_datacentermoid(vccontent, datacenter_name)
    datastoremoid = get_datastoremoid(vccontent, datacenter_name, edge_datastore)
    resourcepoolid = get_edgeresourcepoolmoid(vccontent, datacenter_name, edge_cluster)

    ha_ls_name = kwargs['ha_ls_name']
    # find ha_ls_id in vDS port groups or NSX logical switches
    ha_ls_id = get_vdsportgroupid(vccontent, datacenter_name, ha_ls_name)
    if not ha_ls_id:
        ha_ls_id, ha_ls_switch_params = get_logical_switch(client_session, ha_ls_name)
        if not ha_ls_id:
            print 'ERROR: DLR HA switch {} does NOT exist as VDS port group nor NSX logical switch'.format(ha_ls_name)
            return None

    uplink_ls_name = kwargs['uplink_ls_name']
    uplink_ip = kwargs['uplink_ip']
    uplink_subnet = kwargs['uplink_subnet']
    uplink_dgw = kwargs['uplink_dgw']
    # find uplink_ls_id in vDS port groups or NSX logical switches
    uplink_ls_id = get_vdsportgroupid(vccontent, datacenter_name, uplink_ls_name)
    if not uplink_ls_id:
        uplink_ls_id, uplink_ls_switch_params = get_logical_switch(client_session, uplink_ls_name)
        if not uplink_ls_id:
            print 'ERROR: DLR uplink switch {} does NOT exist as VDS port group ' \
                  'nor NSX logical switch'.format(uplink_ls_name)
            return None

    dlr_id, dlr_params = dlr_create(client_session, dlr_name, dlr_pwd, dlr_size, datacentermoid, datastoremoid,
                                    resourcepoolid, ha_ls_id, uplink_ls_id, uplink_ip, uplink_subnet, uplink_dgw)
    if kwargs['verbose']:
        print dlr_params
    else:
        print 'Distributed Logical Router {} created with the Edge-ID {}'.format(dlr_name, dlr_id)


def dlr_set_dgw(client_session, dlr_id, uplink_dgw):
    """
    This function adds a default gw to one dlr
    :param dlr_id: dlr uuid
    :param uplink_dgw: default gateway ip address
    """
    # get a template dict for the dlr routes
    dlr_static_route_dict = client_session.extract_resource_body_example('routingConfig', 'update')

    # add default gateway to the created dlr if dgw entered
    dlr_static_route_dict['routing']['staticRouting']['defaultRoute']['gatewayAddress'] = uplink_dgw
    del dlr_static_route_dict['routing']['routingGlobalConfig']
    del dlr_static_route_dict['routing']['staticRouting']['staticRoutes']
    del dlr_static_route_dict['routing']['ospf']
    del dlr_static_route_dict['routing']['isis']
    del dlr_static_route_dict['routing']['bgp']

    dlr_static_route = client_session.update('routingConfig', uri_parameters={'edgeId': dlr_id},
                                             request_body_dict=dlr_static_route_dict)
    return dlr_static_route


def _dlr_set_dgw(client_session, **kwargs):
    if not (kwargs['dlr_name'] and kwargs['uplink_dgw']):
        print 'Mandatory parameters [-n NAME] and [--uplink_dgw UPLINK_DGW] missing'
        return None
    dlr_name = kwargs['dlr_name']
    uplink_dgw = kwargs['uplink_dgw']

    dlr_id, dlr_params = dlr_read(client_session, dlr_name)
    if dlr_id:
        dlr_dgw = dlr_set_dgw(client_session, dlr_id, uplink_dgw)
        if dlr_dgw and kwargs['verbose']:
            print json.dumps(dlr_dgw)
        else:
            print 'Default gateway {} added to dlr_name {} / dlr_id {}'.format(uplink_dgw, dlr_name, dlr_id)
    else:
        print 'DLR {} not found'.format(dlr_name)


def dlr_del_dgw(client_session, dlr_id):
    """
    This function deletes a default gw to one dlr
    :param dlr_id: dlr uuid
    """
    # get a template dict for the dlr routes
    dlr_static_route_dict = client_session.extract_resource_body_example('routingConfig', 'update')

    # add default gateway to the created dlr if dgw entered
    # dlr_static_route_dict['routing']['staticRouting']['defaultRoute']['gatewayAddress'] = ""
    del dlr_static_route_dict['routing']['routingGlobalConfig']
    del dlr_static_route_dict['routing']['staticRouting']['staticRoutes']
    del dlr_static_route_dict['routing']['ospf']
    del dlr_static_route_dict['routing']['isis']
    del dlr_static_route_dict['routing']['bgp']

    dlr_static_route = client_session.delete('routingConfig', uri_parameters={'edgeId': dlr_id})
    return dlr_static_route


def _dlr_del_dgw(client_session, **kwargs):
    if not (kwargs['dlr_name']):
        print 'Mandatory parameter [-n NAME] missing'
        return None
    dlr_name = kwargs['dlr_name']

    dlr_id, dlr_params = dlr_read(client_session, dlr_name)
    if dlr_id:
        dlr_dgw = dlr_del_dgw(client_session, dlr_id)
        if dlr_dgw and kwargs['verbose']:
            print json.dumps(dlr_dgw)
        else:
            print 'Default gateway deleted from dlr_name {} / dlr_id {}'.format(dlr_name, dlr_id)
    else:
        print 'DLR {} not found'.format(dlr_name)


def dlr_delete(client_session, dlr_name):
    """
    This function will delete a dlr in NSX
    :param client_session: An instance of an NsxClient Session
    :param dlr_name: The name of the dlr to delete
    :return: returns a tuple, the first item is a boolean indicating success or failure to delete the dlr,
             the second item is a string containing to dlr id of the deleted dlr
    """
    dlr_id, dlr_params = get_edge(client_session, dlr_name)
    if not dlr_id:
        return False, None
    client_session.delete('nsxEdge', uri_parameters={'edgeId': dlr_id})
    return True, dlr_id


def _dlr_delete(client_session, **kwargs):
    dlr_name = kwargs['dlr_name']
    result, dlr_id = dlr_delete(client_session, dlr_name)
    if result and kwargs['verbose']:
        return json.dumps(dlr_id)
    elif result:
        print 'Distributed Logical Router {} with the ID {} has been deleted'.format(dlr_name, dlr_id)
    else:
        print 'Distributed Logical Router deletion failed'


def dlr_read(client_session, dlr_name):
    """
    This funtions retrieves details of a dlr in NSX
    :param client_session: An instance of an NsxClient Session
    :param dlr_name: The name of the dlr to retrieve details from
    :return: returns a tuple, the first item is a string containing the dlr ID, the second is a dictionary
             containing the dlr details retrieved from the API
    """
    dlr_id, dlr_params = get_edge(client_session, dlr_name)
    return dlr_id, dlr_params


def _dlr_read(client_session, **kwargs):
    dlr_name = kwargs['dlr_name']
    dlr_id, dlr_params = dlr_read(client_session, dlr_name)
    if dlr_params and kwargs['verbose']:
        print json.dumps(dlr_params)
    elif dlr_id:
        print 'Distributed Logical Router {} has the ID {}'.format(dlr_name, dlr_id)
    else:
        print 'Distributed Logical Router {} not found'.format(dlr_name)


def dlr_list(client_session):
    """
    This function returns all DLR found in NSX
    :param client_session: An instance of an NsxClient Session
    :return: returns a tuple, the first item is a list of tuples with item 0 containing the DLR Name as string
             and item 1 containing the dlr id as string. The second item contains a list of dictionaries containing
             all DLR details
    """
    all_dist_lr = client_session.read_all_pages('nsxEdges', 'read')
    dist_lr_list = []
    dist_lr_list_verbose = []
    for dlr in all_dist_lr:
        if dlr['edgeType'] == "distributedRouter":
            dist_lr_list.append((dlr['name'], dlr['objectId']))
            dist_lr_list_verbose.append(dlr)
    return dist_lr_list, dist_lr_list_verbose


def _dlr_list_print(client_session, **kwargs):
    dist_lr_list, dist_lr_params = dlr_list(client_session)
    if kwargs['verbose']:
        print dist_lr_params
    else:
        print tabulate(dist_lr_list, headers=["DLR name", "DLR ID"], tablefmt="psql")


def contruct_parser(subparsers):
    parser = subparsers.add_parser('dlr', description="nsxv function for dlr '%(prog)s @params.conf'.",
                                   help="Functions for distributed logical routers",
                                   formatter_class=RawTextHelpFormatter)
    parser.add_argument("command", help="""
    create:         create a new dlr
    read:           return the id of a dlr
    delete:         delete a dlr
    list:           return a list of all dlr
    dgw_set:        set dlr default gateway ip address
    dgw_del:        delete dlr default gateway ip address
    add_interface:  add interface in dlr
    del_interface:  delete interface of dlr
    list_interfaces:list all interfaces of dlr
    """)

    parser.add_argument("-n",
                        "--name",
                        help="dlr name")
    parser.add_argument("-p",
                        "--dlrpassword",
                        help="dlr admin password",
                        default="VMware1!VMware1!")
    parser.add_argument("-s",
                        "--dlrsize",
                        help="dlr size (compact, large, quadlarge, xlarge)",
                        default="compact")
    parser.add_argument("--ha_ls",
                        help="dlr ha LS name")
    parser.add_argument("--uplink_ls",
                        help="dlr uplink logical switch name")
    parser.add_argument("--uplink_ip",
                        help="dlr uplink ip address")
    parser.add_argument("--uplink_subnet",
                        help="dlr uplink subnet")
    parser.add_argument("--uplink_dgw",
                        help="dlr uplink default gateway")
    parser.add_argument("--interface_ls",
                        help="interface logical switch in dlr")
    parser.add_argument("--interface_ip",
                        help="interface ip address in dlr")
    parser.add_argument("--interface_subnet",
                        help="interface subnet in dlr")

    parser.set_defaults(func=_dlr_main)


def _dlr_main(args):
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

    datacenter_name = config.get('defaults', 'datacenter_name')
    edge_datastore = config.get('defaults', 'edge_datastore')
    edge_cluster = config.get('defaults', 'edge_cluster')

    try:
        command_selector = {
            'list': _dlr_list_print,
            'create': _dlr_create,
            'delete': _dlr_delete,
            'read': _dlr_read,
            'dgw_set': _dlr_set_dgw,
            'dgw_del': _dlr_del_dgw,
            'add_interface': _dlr_add_interface,
            'del_interface': _dlr_del_interface,
            'list_interfaces': _dlr_list_interfaces,
        }
        command_selector[args.command](client_session, vccontent=vccontent,
                                       dlr_name=args.name, dlr_pwd=args.dlrpassword, dlr_size=args.dlrsize,
                                       datacenter_name=datacenter_name, edge_datastore=edge_datastore,
                                       edge_cluster=edge_cluster, ha_ls_name=args.ha_ls,
                                       uplink_ls_name=args.uplink_ls, uplink_ip=args.uplink_ip,
                                       uplink_subnet=args.uplink_subnet, uplink_dgw=args.uplink_dgw,
                                       interface_ls_name=args.interface_ls, interface_ip=args.interface_ip,
                                       interface_subnet=args.interface_subnet,
                                       verbose=args.verbose)

    except KeyError:
        print('Unknown command')


def main():
    main_parser = argparse.ArgumentParser()
    subparsers = main_parser.add_subparsers()
    contruct_parser(subparsers)
    args = main_parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
