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

from pyVim.connect import SmartConnect
from pyVmomi import vim
import ssl


VIM_TYPES = {'datacenter': [vim.Datacenter],
             'dvs_name': [vim.dvs.VmwareDistributedVirtualSwitch],
             'datastore_name': [vim.Datastore],
             'resourcepool_name': [vim.ResourcePool],
             'host': [vim.HostSystem]}


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
    if context:
        service_instance = SmartConnect(host=vchost, user=user, pwd=pwd, sslContext=context)
    else:
        service_instance = SmartConnect(host=vchost, user=user, pwd=pwd)

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
    datacenter_list = content.rootFolder.childEntity
    for datacenter in datacenter_list:
        if datacenter.name == datacenter_name:
            datacentermoid = datacenter._moId
            return datacentermoid.encode("ascii")
    return None


def get_datastoremoid(content, datacenter_name, edge_datastore):
    datacenter_list = content.rootFolder.childEntity
    for datacenter in datacenter_list:
        if datacenter.name == datacenter_name:
            for datastore in datacenter.datastore:
                if datastore.name == edge_datastore:
                    datastorename = datastore._moId
                    return datastorename.encode("ascii")
    return None


def get_edgeresourcepoolmoid(content, datacenter_name, edge_cluster):
    datacenter_list = content.rootFolder.childEntity
    for datacenter in datacenter_list:
        if datacenter.name == datacenter_name:
            cluster_list = datacenter.hostFolder.childEntity
            for cluster in cluster_list:
                if cluster.name == edge_cluster:
                    resourcepoolid = cluster.resourcePool._moId
                    return resourcepoolid.encode("ascii")
    return None


def get_vdsportgroupid(content, datacenter_name, switch_name):
    datacenter_list = content.rootFolder.childEntity
    vdsportgroupid = ""
    for datacenter in datacenter_list:
        if datacenter.name == datacenter_name:
            network_list = datacenter.network
            for network in network_list:
                if network.name == switch_name:
                    vdsportgroupid = network._moId
    if vdsportgroupid:
        return vdsportgroupid.encode("ascii")
    else:
        return None


def check_for_parameters(mandatory, args):
    try:
        for param in mandatory:
            if args[param] == None:
                print 'You are missing the mandatory parameter: {}'.format(param)
                return None
    except KeyError:
        print 'You are missing the mandatory parameter: {}'.format(param)
        return None

    return True