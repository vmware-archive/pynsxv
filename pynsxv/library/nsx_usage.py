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
from tabulate import tabulate
from nsxramlclient.client import NsxClient
from libutils import connect_to_vc
from libutils import VIM_TYPES
from libutils import get_all_objs


def host_prep_state(session):
    resource_status = session.read('statusResourceType', uri_parameters={'resourceType': 'ClusterComputeResource'})
    enabled_clusters = session.normalize_list_return(resource_status['body']['resourceStatuses']['resourceStatus'])
    clusters = []
    for cluster in enabled_clusters:
        feature_status = cluster['nwFabricFeatureStatus']
        dfw_enabled = [feature['enabled'] for feature in feature_status
                       if feature['featureId'] == 'com.vmware.vshield.firewall'][0]
        clusters.append((cluster['resource']['objectId'], cluster['resource']['name'], dfw_enabled))

    hosts = []
    for cluster_moid, cluster_name, dfw_enabled in clusters:
        hosts_status = session.read('childStatus', uri_parameters={'parentResourceID': cluster_moid})
        enabled_hosts = session.normalize_list_return(hosts_status['body']['resourceStatuses']['resourceStatus'])
        hosts.extend([(host['resource']['name'], host['resource']['scope']['name'],
                       host['resource']['objectId'], host['resource']['scope']['id'],
                       dfw_enabled) for host in enabled_hosts])

    prepared_hosts_count = len(hosts)
    dfw_enabled_hosts_count = len([host for host in hosts if host[4] == 'true'])

    return prepared_hosts_count, dfw_enabled_hosts_count, hosts


def get_host_info(vccontent, host_list):
    host_info = []
    host_modict = get_all_objs(vccontent, VIM_TYPES['host'])
    for host_name in [host[0] for host in host_list]:
        print 'retrieving details (hardware & vms) for host {} ....'.format(host_name),
        host_object = [host_mo for host_mo in host_modict if host_mo.name == host_name][0]
        cpu_count = host_object.hardware.cpuInfo.numCpuPackages
        #TODO: Filter service VMs out of the count
        vm_moids = [vm._moId for vm in host_object.vm]
        vm_count = len(vm_moids)
        host_info.extend([(host_name, cpu_count, vm_count)])
        print 'Done'
    return host_info


def calculate_socket_usage(host_list, host_info):
    nsx_socket_count = 0
    dfw_scocket_count = 0
    for host in host_info:
        for nsx_host in host_list:
            if host[0] == nsx_host[0]:
                if nsx_host[4] == 'true':
                    dfw_scocket_count += int(host[1])
                nsx_socket_count += int(host[1])
    return nsx_socket_count, dfw_scocket_count


def ls_state(session):
    all_logical_switches = session.read_all_pages('logicalSwitchesGlobal', 'read')
    ls_list = [(ls['name'], ls['objectId']) for ls in all_logical_switches if ls['isUniversal'] == 'false']
    uls_list = [(ls['name'], ls['objectId']) for ls in all_logical_switches if ls['isUniversal'] == 'true']
    return len(ls_list), ls_list, len(uls_list), uls_list


def edge_state(session):
    edge_status = session.read_all_pages('nsxEdges', 'read')
    esg_list = [(edge['objectId'], edge['name']) for edge in edge_status if edge['edgeType'] == 'gatewayServices']
    dlr_list = [(edge['objectId'], edge['name']) for edge in edge_status if edge['edgeType'] == 'distributedRouter']
    return len(esg_list), esg_list, len(dlr_list), dlr_list


def _single_esg_feature_collect(session, edge_id, edge_name):
    print 'retrieving the features for Services Gateway {}/{} ....'.format(edge_name, edge_id),
    edge_details = session.read('nsxEdge', uri_parameters={'edgeId': edge_id})['body']
    print 'Done'
    feature_map = {}
    for feature in edge_details['edge']['features'].keys():
        try:
            feature_map.update({feature: edge_details['edge']['features'][feature]['enabled']})
        except TypeError:
            pass

    return_tupple = (edge_name, edge_id, feature_map['loadBalancer'], feature_map['firewall'],
                     feature_map['routing'], feature_map['ipsec'], feature_map['l2Vpn'],
                     feature_map['sslvpnConfig'])

    return return_tupple


def esg_features_collect(session, edge_list):
    feature_list = []
    for edge_name, edge_id in edge_list:
        feature_list.append(_single_esg_feature_collect(session, edge_name, edge_id))
    return feature_list


def contruct_parser(subparsers):
    parser = subparsers.add_parser('usage', description="Functions to retrieve NSX-v usage statistics",
                                   help="Functions to retrieve NSX-v usage statistics")
    parser.set_defaults(func=_usage_main)


def _usage_main(args):
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

    print 'retrieving the hosts prepared for NSX ....',
    host_count, dfw_enabled_hosts, host_list = host_prep_state(client_session)
    print 'Done'
    if args.verbose:
        print tabulate(host_list, headers=["Host name", "Cluster name", "Host moid", "Cluster moid", "DFW enabled"],
                       tablefmt="psql")

    print 'retrieving the hosts detailed information ....'
    host_info = get_host_info(vccontent, host_list)
    if args.verbose:
        print tabulate(host_info, headers=["Host name", "CPU Socket count", "VM count"], tablefmt="psql")

    print 'retrieving the number of NSX logical switches ....',
    ls_count, ls_list, uls_count, uls_list = ls_state(client_session)
    print 'Done'
    if args.verbose:
        print tabulate(ls_list, headers=["Logical switch name", "Logical switch Id"], tablefmt="psql")
        print tabulate(uls_list, headers=["Universal Logical switch name", "Logical switch Id"], tablefmt="psql")

    print 'retrieving the number of NSX gateways (ESGs and DLRs) ....',
    esg_count, esg_list, dlr_count, dlr_list = edge_state(client_session)
    print 'Done'
    if args.verbose:
        print tabulate(esg_list, headers=["Edge service gw name", "Edge service gw Id"], tablefmt="psql")
        print tabulate(dlr_list, headers=["Logical router name", "Logical router Id"], tablefmt="psql")

    edge_feature_list = esg_features_collect(client_session, esg_list)
    if args.verbose:
        print tabulate(edge_feature_list, headers=["Edge service gw name", "Edge service gw Id", "Loadbalancer",
                                                   "Firewall", "Routing", "IPSec", "L2VPN", "SSL-VPN"], tablefmt="psql")

    lb_esg = len([edge for edge in edge_feature_list if edge[2] == 'true'])
    fw_esg = len([edge for edge in edge_feature_list if edge[3] == 'true'])
    rt_esg = len([edge for edge in edge_feature_list if edge[4] == 'true'])
    ipsec_esg = len([edge for edge in edge_feature_list if edge[5] == 'true'])
    l2vpn_esg = len([edge for edge in edge_feature_list if edge[6] == 'true'])
    sslvpn_esg = len([edge for edge in edge_feature_list if edge[7] == 'true'])
    nsx_sockets, dfw_sockets = calculate_socket_usage(host_list, host_info)

    output_table = [('Number of hosts prepared for NSX', str(host_count)),
                    ('Number of hosts enabled to use DFW', str(dfw_enabled_hosts)),
                    ('Number of CPU Sockets enabled for NSX', str(nsx_sockets)),
                    ('Number of CPU Sockets enabled for DFW', str(dfw_sockets)),
                    ('Number of local logical switches', str(ls_count)),
                    ('Number of universal logical switches', str(uls_count)),
                    ('Number of Edge services Gateways', str(esg_count)),
                    ('Number of Distributed Routers', str(dlr_count)),
                    ('Number of Service Gateways with Loadbalancing Enabled', str(lb_esg)),
                    ('Number of Service Gateways with Firewall Enabled', str(fw_esg)),
                    ('Number of Service Gateways with Routing Enabled', str(rt_esg)),
                    ('Number of Service Gateways with IPSec Enabled', str(ipsec_esg)),
                    ('Number of Service Gateways with L2VPN Enabled', str(l2vpn_esg)),
                    ('Number of Service Gateways with SSL-VPN Enabled', str(sslvpn_esg))]

    print '\n\nNSX usage summary:'
    print tabulate(output_table, headers=["Feature / Property / Type", "Count"], tablefmt="psql")


def main():
    main_parser = argparse.ArgumentParser()
    subparsers = main_parser.add_subparsers()
    contruct_parser(subparsers)
    args = main_parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
