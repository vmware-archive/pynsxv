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

from pyVim.connect import SmartConnect
from pyVmomi import vim
import ssl

__author__ = 'Dimitri Desmidt, Emanuele Mazza, Yves Fauser, Andreas La Quiante'


VIM_TYPES = {'datacenter': [vim.Datacenter],
             'dvs_name': [vim.dvs.VmwareDistributedVirtualSwitch],
             'datastore_name': [vim.Datastore],
             'resourcepool_name': [vim.ResourcePool],
             'host': [vim.HostSystem],
             'dc': [vim.Datacenter],
             'cluster': [vim.ClusterComputeResource],
             'vm': [vim.VirtualMachine],
             'dportgroup': [vim.DistributedVirtualPortgroup],
             'portgroup': [vim.Network],
             'respool': [vim.ResourcePool],
             'vapp': [vim.ResourcePool],
             'vnic': [vim.VirtualMachine]}


def nametovalue (vccontent, client_session, name, type):
    if type == 'ipset':
        ipset_id = str()
        scopename = 'globalroot-0'
        ipsets = get_ipsets(client_session, scopename)
        ipsets_list = ipsets.items()[1][1]['list']['ipset']
        for i, val in enumerate(ipsets_list):
            if str(val['name']) == name:
                ipset_id = val['objectId']
        return str(ipset_id)

    elif type == 'macset':
        macset_id = str()
        scopename = 'globalroot-0'
        macsets = get_macsets(client_session, scopename)
        macsets_list = macsets.items()[1][1]['list']['macset']
        for i, val in enumerate(macsets_list):
            if str(val['name']) == name:
                macset_id = val['objectId']
        return str(macset_id)

    elif type == 'ls':
        ls_id = str()
        ls_id, ls_param = get_logical_switch(client_session, name)
        return str(ls_id)

    elif type == 'secgroup':
        secgroup_id = str()
        scopename = 'globalroot-0'
        secgroups = get_secgroups(client_session, scopename)
        secgroups_list = secgroups.items()[1][1]['list']['securitygroup']
        for i, val in enumerate(secgroups_list):
            if str(val['name']) == name:
                secgroup_id = val['objectId']
        return str(secgroup_id)

    else:
        obj = get_mo_by_name(vccontent, name, VIM_TYPES[type])
        return str(obj._moId)


def get_scope(client_session, transport_zone_name):
    """
    :param client_session: An instance of an NsxClient Session
    :param transport_zone_name: The Name of the Scope (Transport Zone)
    :return: A tuple, with the first item being the scope id as string of the first Scope found with the right name
             and the second item being a dictionary of the scope parameters as return by the NSX API
    """
    try:
        vdn_scopes = client_session.read('vdnScopes', 'read')['body']
        vdn_scope_list = client_session.normalize_list_return(vdn_scopes['vdnScopes'])
        vdn_scope = [scope['vdnScope'] for scope in vdn_scope_list
                     if scope['vdnScope']['name'] == transport_zone_name][0]
    except KeyError:
        return None, None

    return vdn_scope['objectId'], vdn_scope


def get_ipsets(client_session, scopename):
    #TODO documentation
    ip_sets = client_session.read('ipsetList', uri_parameters={'scopeMoref': scopename})
    return ip_sets


def get_macsets(client_session, scopename):
    #TODO documentation
    mac_sets = client_session.read('macsetScopes', uri_parameters={'scopeId': scopename})
    return mac_sets


def get_secgroups(client_session, scopename):
    #TODO documentation
    secgroups = client_session.read('secGroupScope', uri_parameters={'scopeId': scopename})
    return secgroups


def get_logical_switch(client_session, logical_switch_name):
    """
    :param client_session: An instance of an NsxClient Session
    :param logical_switch_name: The name of the logical switch searched
    :return: A tuple, with the first item being the logical switch id as string of the first Scope found with the
             right name and the second item being a dictionary of the logical parameters as return by the NSX API
    """
    all_lswitches = client_session.read_all_pages('logicalSwitchesGlobal', 'read')
    try:
        logical_switch_params = [scope for scope in all_lswitches if scope['name'] == logical_switch_name][0]
        logical_switch_id = logical_switch_params['objectId']
    except IndexError:
        return None, None

    return logical_switch_id, logical_switch_params


def get_mo_by_name(content, searchedname, vim_type):
    mo_dict = get_all_objs(content, vim_type)
    for obj in mo_dict:
        if obj.name == searchedname:
            return obj
    return None


def get_all_objs(content, vimtype):
    obj = {}
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)

    for managed_object_ref in container.view:
        obj.update({managed_object_ref: managed_object_ref.name})
    container.Destroy()
    return obj


def connect_to_vc(vchost, user, pwd):
    # Disabling SSL certificate verification
    if hasattr(ssl, 'SSLContext'):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_NONE
    else:
        context = None

    if vchost.find(':') != -1:
        host, port = vchost.split(':')
    else:
        host = vchost
        port = 443

    if context:
        service_instance = SmartConnect(host=host, port=port, user=user, pwd=pwd, sslContext=context)
    else:
        service_instance = SmartConnect(host=host, port=port, user=user, pwd=pwd)

    return service_instance.RetrieveContent()


def get_edge(client_session, edge_name):
    """
    :param client_session: An instance of an NsxClient Session
    :param edge_name: The name of the edge searched
    :return: A tuple, with the first item being the edge or dlr id as string of the first Scope found with the
             right name and the second item being a dictionary of the logical parameters as return by the NSX API
    """
    all_edge = client_session.read_all_pages('nsxEdges', 'read')

    try:
        edge_params = [scope for scope in all_edge if scope['name'] == edge_name][0]
        edge_id = edge_params['objectId']

    except IndexError:
        return None, None

    return edge_id, edge_params


def get_datacentermoid(content, datacenter_name):
    datacenter_mo = get_mo_by_name(content, datacenter_name, VIM_TYPES['datacenter'])
    if datacenter_mo:
        return str(datacenter_mo._moId)
    else:
        return None


def get_datastoremoid(content, edge_datastore):
    datastore_mo = get_mo_by_name(content, edge_datastore, VIM_TYPES['datastore_name'])
    if datastore_mo:
        return str(datastore_mo._moId)
    else:
        return None


def get_edgeresourcepoolmoid(content, edge_cluster):
    cluser_mo = get_mo_by_name(content, edge_cluster, VIM_TYPES['cluster'])
    if cluser_mo:
        return str(cluser_mo._moId)
    else:
        return None


def get_vdsportgroupid(content, switch_name):
    portgroup_mo = get_mo_by_name(content, switch_name, VIM_TYPES['dportgroup'])
    if portgroup_mo:
        return str(portgroup_mo._moId)
    else:
        return None


def get_vm_by_name(content, vm_name):
    vm_mo = get_mo_by_name(content, vm_name, VIM_TYPES['vm'])
    if vm_mo:
        return str(vm_mo._moId)
    else:
        return None


def check_for_parameters(mandatory, args):
    param = None
    try:
        for param in mandatory:
            if not args[param]:
                print 'You are missing the mandatory parameter: {}'.format(param)
                return None
    except KeyError:
        print 'You are missing the mandatory parameter: {}'.format(param)
        return None

    return True


def dfw_rule_list_helper(client_session, dfw_section, rule_list):
    source_list = list()
    destination_list = list()
    service_list = list()
    applyto_list = list()

    for rptr in dfw_section:
        rule_id = rptr['@id']
        if 'name' in rptr:
            rule_name = rptr['name']
        else:
            rule_name = str('')
        rule_action = rptr['action']
        rule_direction = rptr['direction']
        rule_packetype = rptr['packetType']
        rule_section_id = rptr['sectionId']

        if 'sources' in rptr:
            sources = client_session.normalize_list_return(rptr['sources']['source'])
            for srcptr in sources:
                if srcptr['type'] == 'Ipv4Address':
                    rule_source = str(srcptr['value'])
                elif srcptr['type'] == 'VirtualMachine':
                    rule_source = str(srcptr['name'])
                else:
                    rule_source = srcptr['name']
                source_list.append(rule_source)
            source_list = " - ".join(source_list)
        else:
            source_list = 'any'

        if 'destinations' in rptr:
            destinations = client_session.normalize_list_return(rptr['destinations']['destination'])
            for dscptr in destinations:
                if dscptr['type'] == 'Ipv4Address':
                    rule_destination = dscptr['value']
                elif dscptr['type'] == 'VirtualMachine':
                    rule_destination = dscptr['name']
                else:
                    rule_destination = dscptr['name']
                destination_list.append(rule_destination)
            destination_list = ' - '.join(destination_list)
        else:
            destination_list = 'any'

        if 'services' in rptr:
            services = client_session.normalize_list_return(rptr['services']['service'])
            for srvcptr in services:
                if 'name' in srvcptr:
                    rule_services = srvcptr['name']
                    service_list.append(rule_services)
                if 'protocol' in srvcptr:
                    if 'sourcePort' in srvcptr:
                        source_port = str(srvcptr['sourcePort'])
                    else:
                        source_port = 'any'
                    if 'destinationPort' in srvcptr:
                        destination_port = str(srvcptr['destinationPort'])
                    else:
                        destination_port = 'any'
                    protocol = srvcptr['protocolName']
                    rule_services = protocol + ':' + source_port + ':' + destination_port
                    service_list.append(rule_services)
            service_list = ' | '.join(service_list)
        else:
            service_list = 'any'

        if 'appliedToList' in rptr:
            applyto = client_session.normalize_list_return(rptr['appliedToList']['appliedTo'])
            for apptr in applyto:
                rule_applyto = apptr['name']
                applyto_list.append(rule_applyto)
            applyto_list = ' - '.join(applyto_list)
        else:
            applyto_list = 'any'

        rule_list.append([rule_id, rule_name, source_list, destination_list, service_list, rule_action,
                                     rule_direction, rule_packetype, applyto_list, rule_section_id])
        source_list = list()
        destination_list = list()
        service_list = list()
        applyto_list = list()

    return rule_list