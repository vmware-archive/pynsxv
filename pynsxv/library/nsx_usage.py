#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2015 VMware, Inc. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
# to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions
# of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

__author__ = 'yfauser'

import argparse
import ConfigParser
from tabulate import tabulate
from nsxramlclient.client import NsxClient


def host_prep_state(session):
    resource_status = session.read('statusResourceType', uri_parameters={'resourceType': 'ClusterComputeResource'})
    enabled_clusters = session.normalize_list_return(resource_status['body']['resourceStatuses']['resourceStatus'])
    clusters = [(cluster['resource']['objectId'], cluster['resource']['name']) for cluster in enabled_clusters]

    hosts = []
    for cluster_moid, cluster_name in clusters:
        hosts_status = session.read('childStatus', uri_parameters={'parentResourceID': cluster_moid})
        enabled_hosts = session.normalize_list_return(hosts_status['body']['resourceStatuses']['resourceStatus'])
        hosts.extend([(host['resource']['name'], host['resource']['scope']['name'],
                       host['resource']['objectId'], host['resource']['scope']['id']) for host in enabled_hosts])

    return len(hosts), hosts


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
    config.read(args.ini)

    output_table = []

    client_session = NsxClient(config.get('nsxraml', 'nsxraml_file'), config.get('nsxv', 'nsx_manager'),
                               config.get('nsxv', 'nsx_username'), config.get('nsxv', 'nsx_password'), debug=debug)

    print 'retrieving the hosts prepared for NSX ....',
    host_count, host_list = host_prep_state(client_session)
    print 'Done'
    if args.verbose:
        print tabulate(host_list, headers=["Host name", "Cluster name", "Host moid", "Cluster moid"], tablefmt="psql")

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

    output_table.append(('Number of hosts prepared for NSX', str(host_count)))
    output_table.append(('Number of local logical switches', str(ls_count)))
    output_table.append(('Number of universal logical switches', str(uls_count)))
    output_table.append(('Number of Edge services Gateways', str(esg_count)))
    output_table.append(('Number of Distributed Routers', str(dlr_count)))
    output_table.append(('Number of Service Gateways with Loadbalancing Enabled', str(lb_esg)))
    output_table.append(('Number of Service Gateways with Firewall Enabled', str(fw_esg)))
    output_table.append(('Number of Service Gateways with Routing Enabled', str(rt_esg)))
    output_table.append(('Number of Service Gateways with IPSec Enabled', str(ipsec_esg)))
    output_table.append(('Number of Service Gateways with L2VPN Enabled', str(l2vpn_esg)))
    output_table.append(('Number of Service Gateways with SSL-VPN Enabled', str(sslvpn_esg)))
    print tabulate(output_table, headers=["Feature / Property / Type", "Count"], tablefmt="psql")


def main():
    main_parser = argparse.ArgumentParser()
    subparsers = main_parser.add_subparsers()
    contruct_parser(subparsers)
    args = main_parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
