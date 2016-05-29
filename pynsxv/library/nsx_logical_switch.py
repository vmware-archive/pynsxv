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

__author__ = 'Dimitri Desmidt, Emanuele Mazza, Yves Fauser'

import argparse
import ConfigParser
import json
from libutils import get_scope
from libutils import get_logical_switch
from tabulate import tabulate
from nsxramlclient.client import NsxClient
from argparse import RawTextHelpFormatter


def logical_switch_create(client_session, transport_zone, logical_switch_name, control_plane_mode=None):
    """
    This function will create a new logical switch in NSX
    :param client_session: An instance of an NsxClient Session
    :param transport_zone: The name of the Scope (Transport Zone)
    :param logical_switch_name: The name that will be assigned to the new logical switch
    :param control_plane_mode: (Optional) Control Plane Mode, uses the Transport Zone default if not specified
    :return: returns a tuple, the first item is the logical switch ID in NSX as string, the second is string
             containing the logical switch URL location as returned from the API
    """
    vdn_scope_id, vdn_scope = get_scope(client_session, transport_zone)
    assert vdn_scope_id, 'The Transport Zone you defined could not be found'
    if not control_plane_mode:
        control_plane_mode = vdn_scope['controlPlaneMode']

    # get a template dict for the lswitch create
    lswitch_create_dict = client_session.extract_resource_body_example('logicalSwitches', 'create')

    # fill the details for the new lswitch in the body dict
    lswitch_create_dict['virtualWireCreateSpec']['controlPlaneMode'] = control_plane_mode
    lswitch_create_dict['virtualWireCreateSpec']['name'] = logical_switch_name
    lswitch_create_dict['virtualWireCreateSpec']['tenantId'] = ''

    # create new lswitch
    new_ls = client_session.create('logicalSwitches', uri_parameters={'scopeId': vdn_scope_id},
                                   request_body_dict=lswitch_create_dict)
    return new_ls['body'], new_ls['location']


def _logical_switch_create(client_session, **kwargs):
    transport_zone = kwargs['transport_zone']
    logical_switch_name = kwargs['logical_switch_name']
    if not logical_switch_name:
        print 'You must specify a logical switch name for create'
        return None
    logical_switch_id, logical_switch_params = logical_switch_create(client_session, transport_zone,
                                                                     logical_switch_name)
    if kwargs['verbose']:
        print logical_switch_params
    else:
        print 'Logical Switch {} created with the ID {}'.format(logical_switch_name, logical_switch_id)


def logical_switch_delete(client_session, logical_switch_name):
    """
    This function will delete a logical switch in NSX
    :param client_session: An instance of an NsxClient Session
    :param logical_switch_name: The name of the logical switch to delete
    :return: returns a tuple, the first item is a boolean indicating success or failure to delete the LS,
             the second item is a string containing to logical switch id of the deleted LS
    """
    logical_switch_id, logical_switch_params = get_logical_switch(client_session, logical_switch_name)
    if not logical_switch_id:
        return False, None
    client_session.delete('logicalSwitch', uri_parameters={'virtualWireID': logical_switch_id})
    return True, logical_switch_id


def _logical_switch_delete(client_session, **kwargs):
    logical_switch_name = kwargs['logical_switch_name']
    if not logical_switch_name:
        print 'You must specify a logical switch name for deletion'
        return None
    result, logical_switch_id = logical_switch_delete(client_session, logical_switch_name)
    if result and kwargs['verbose']:
        return json.dumps(logical_switch_id)
    elif result:
        print 'Logical Switch {} with the ID {} has been deleted'.format(logical_switch_name, logical_switch_id)
    else:
        print 'Logical Switch deletion failed'


def logical_switch_read(client_session, logical_switch_name):
    """
    This funtions retrieves details of a logical switch in NSX
    :param client_session: An instance of an NsxClient Session
    :param logical_switch_name: The name of the logical switch to retrieve details from
    :return: returns a tuple, the first item is a string containing the logical switch ID, the second is a dictionary
             containing the logical switch details retrieved from the API
    """
    logical_switch_id, logical_switch_params = get_logical_switch(client_session, logical_switch_name)
    return logical_switch_id, logical_switch_params


def _logical_switch_read(client_session, **kwargs):
    logical_switch_name = kwargs['logical_switch_name']
    if not logical_switch_name:
        print 'You must specify a logical switch name for read'
        return None
    logical_switch_id, logical_switch_params = logical_switch_read(client_session, logical_switch_name)
    if logical_switch_params and kwargs['verbose']:
        print json.dumps(logical_switch_params)
    elif logical_switch_id:
        print 'Logical Switch {} has the ID {}'.format(logical_switch_name, logical_switch_id)
    else:
        print 'Logical Switch {} not found'.format(logical_switch_name)


def logical_switch_list(client_session):
    """
    This function returns all logical switches found in NSX
    :param client_session: An instance of an NsxClient Session
    :return: returns a tuple, the first item is a list of tuples with item 0 containing the LS Name as string
             and item 1 containing the LS id as string. The second item contains a list of dictionaries containing
             all logical switch details
    """
    all_logical_switches = client_session.read_all_pages('logicalSwitchesGlobal', 'read')
    switch_list = []
    for ls in all_logical_switches:
        try:
            lsname = ls['name']
        except KeyError:
            lsname = '<empty name>'
        switch_list.append((lsname, ls['objectId']))
    return switch_list, all_logical_switches


def _logical_switch_list_print(client_session, **kwargs):
    switches_list, switches_params = logical_switch_list(client_session)
    if kwargs['verbose']:
        print switches_params
    else:
        print tabulate(switches_list, headers=["LS name", "LS ID"], tablefmt="psql")


def contruct_parser(subparsers):
    parser = subparsers.add_parser('lswitch', description="Functions for logical switches",
                                   help="Functions for logical switches",
                                   formatter_class=RawTextHelpFormatter)

    parser.add_argument("command", help="""
    create: create a new logical switch
    read:   return the virtual wire id of a logical switch
    delete: delete a logical switch"
    list:   return a list of all logical switches
    """)

    parser.add_argument("-t",
                        "--transport_zone",
                        help="nsx transport zone")
    parser.add_argument("-n",
                        "--name",
                        help="logical switch name, needed for create, read and delete")

    parser.set_defaults(func=_lswitch_main)


def _lswitch_main(args):
    if args.debug:
        debug = True
    else:
        debug = False

    config = ConfigParser.ConfigParser()
    assert config.read(args.ini), 'could not read config file {}'.format(args.ini)

    if args.transport_zone:
        transport_zone = args.transport_zone
    else:
        transport_zone = config.get('defaults', 'transport_zone')

    client_session = NsxClient(config.get('nsxraml', 'nsxraml_file'), config.get('nsxv', 'nsx_manager'),
                               config.get('nsxv', 'nsx_username'), config.get('nsxv', 'nsx_password'), debug=debug)

    try:
        command_selector = {
            'list': _logical_switch_list_print,
            'create': _logical_switch_create,
            'delete': _logical_switch_delete,
            'read': _logical_switch_read,
            }
        command_selector[args.command](client_session, transport_zone=transport_zone,
                                       logical_switch_name=args.name, verbose=args.verbose)
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
