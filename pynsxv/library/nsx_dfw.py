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
from tabulate import tabulate
from nsxramlclient.client import NsxClient
from argparse import RawTextHelpFormatter
from libutils import dfw_rule_list_helper


def dfw_section_list(client_session):
    """
    This function returns all the sections of the NSX distributed firewall
    :param client_session: An instance of an NsxClient Session
    :return returns
            - for each of the three available sections types (L2, L3Redirect, L3) a list with item 0 containing the
              section name as string, item 1 containing the section id as string, item 2 containing the section type
              as a string
            - a dictionary containing all sections' details, including dfw rules
    """
    all_dfw_sections = client_session.read('dfwConfig')['body']['firewallConfiguration']
    l2_dfw_sections = all_dfw_sections['layer2Sections']['section']
    l3r_dfw_sections = all_dfw_sections['layer3RedirectSections']['section']
    l3_dfw_sections = all_dfw_sections['layer3Sections']['section']

    l2_section_list = []
    l3r_section_list = []
    l3_section_list = []

    for sl in l2_dfw_sections:
        try:
            section_name = sl['@name']
        except KeyError:
            section_name = '<empty name>'
        l2_section_list.append((section_name, sl['@id'], sl['@type']))

    for sl in l3r_dfw_sections:
        try:
            section_name = sl['@name']
        except KeyError:
            section_name = '<empty name>'
        l3r_section_list.append((section_name, sl['@id'], sl['@type']))

    for sl in l3_dfw_sections:
        try:
            section_name = sl['@name']
        except KeyError:
            section_name = '<empty name>'
        l3_section_list.append((section_name, sl['@id'], sl['@type']))

    return l2_section_list, l3r_section_list, l3_section_list, all_dfw_sections

def _dfw_section_list_print(client_session, **kwargs):
    l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
    if kwargs['verbose']:
        print detailed_dfw_sections
    else:
        print tabulate(l2_section_list, headers=["Name", "ID", "Type"], tablefmt="psql")
        print tabulate(l3r_section_list, headers=["Name", "ID", "Type"], tablefmt="psql")
        print tabulate(l3_section_list, headers=["Name", "ID", "Type"], tablefmt="psql")




def dfw_rule_list(client_session):
    """
    This function returns all the rules of the NSX distributed firewall
    :param client_session: An instance of an NsxClient Session
    :return returns
            - a tabular view of all the  dfw rules defined across L2, L3, L3Redirect
            - ( verbose option ) a list containing as many list as the number of dfw rules defined across
              L2, L3, L3Redirect (in this order). For each rule, these fields are returned:
              "ID", "Name", "Source", "Destination", "Service", "Action", "Direction", "Packet Type", "Applied-To",
              "ID (Section)"
    """
    all_dfw_sections_response = client_session.read('dfwConfig')
    all_dfw_sections = client_session.normalize_list_return(all_dfw_sections_response['body']['firewallConfiguration'])

    l2_dfw_sections = all_dfw_sections[0]['layer2Sections']['section']
    l3r_dfw_sections = all_dfw_sections[0]['layer3RedirectSections']['section']
    l3_dfw_sections = all_dfw_sections[0]['layer3Sections']['section']
    #print ''
    #print l2_dfw_sections
    #print ''

    if 'rule' in l2_dfw_sections[0]:
        rule_list = list()
        for sptr in l2_dfw_sections:
            section_rules = client_session.normalize_list_return(sptr['rule'])
            l2_rule_list = dfw_rule_list_helper(client_session, section_rules, rule_list)
    else:
        l2_rule_list = []

    if 'rule' in l3_dfw_sections[0]:
        rule_list = list()
        for sptr in l3_dfw_sections:
            section_rules = client_session.normalize_list_return(sptr['rule'])
            l3_rule_list = dfw_rule_list_helper(client_session, section_rules, rule_list)
    else:
        l3_rule_list = []

    if 'rule' in l3r_dfw_sections[0]:
        rule_list = list()
        for sptr in l3r_dfw_sections:
            section_rules = client_session.normalize_list_return(sptr['rule'])
            l3r_rule_list = dfw_rule_list_helper(client_session, section_rules, rule_list)
    else:
        l3r_rule_list = []

    return l2_rule_list, l3_rule_list, l3r_rule_list

def _dfw_rule_list_print(client_session, **kwargs):
    l2_rule_list, l3_rule_list, l3r_rule_list = dfw_rule_list(client_session)
    if kwargs['verbose']:
        print l2_rule_list, l3_rule_list, l3r_rule_list
    else:
        print ''
        print '*** ETHERNET RULES ***'
        print tabulate(l2_rule_list, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                              "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")
        print ''
        print '*** LAYER 3 RULES ***'
        print tabulate(l3_rule_list, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                              "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")

        print''
        print '*** REDIRECT RULES ***'
        print tabulate(l3r_rule_list, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                                "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")




def dfw_section_read(client_session, dfw_section_id):
    """
    This funtions retrieves details of a dfw section given its id
    :param client_session: An instance of an NsxClient Session
    :param dfw_section_id: The ID of the dfw section to retrieve details from
    :return: returns
            - a list with item 0 containing the section name as string, item 1 containing the section id as string,
            item 2 containing the section type, item 3 containing the section etag as a string
            - ( verbose option ) a list of dictionaries containing all sections's details
    """
    section_list = []
    dfw_section_id = str(dfw_section_id)
    uri_parameters={'sectionId': dfw_section_id}

    dfwL3_section_details = client_session.read('dfwL3SectionId', uri_parameters)
    #dfwL2_section_details = client_session.read('dfwL2SectionId', uri_parameters)

    section_name = dfwL3_section_details['body']['section']['@name']
    section_id =  dfwL3_section_details['body']['section']['@id']
    section_type = dfwL3_section_details['body']['section']['@type']
    section_etag =  dfwL3_section_details['Etag']
    section_list.append((section_name, section_id, section_type, section_etag))

    return section_list, dfwL3_section_details

def _dfw_section_read_print(client_session, **kwargs):
    if not (kwargs['dfw_section_id']):
        print ('Mandatory parameters missing: [-sid SECTION ID]')
        return None
    dfw_section_id = kwargs['dfw_section_id']
    section_list, dfwL3_section_details = dfw_section_read(client_session, dfw_section_id)

    if kwargs['verbose']:
        print dfwL3_section_details
    else:
        print tabulate(section_list, headers=["Name", "ID", "Type", "Etag"], tablefmt="psql")


def contruct_parser(subparsers):
    parser = subparsers.add_parser('dfw', description="Functions for distributed firewall",
                                   help="Functions for distributed firewall",
                                   formatter_class=RawTextHelpFormatter)

    parser.add_argument("command", help="""
    list_sections:   return a list of all distributed firewall's sections
    read_section:    return the details of a dfw section given its id
    list_rules:      return a list of all distributed firewall's rules
    create_section:  TBD
    delete_section:  TBD
    """)

    parser.add_argument("-sid",
                        "--section_id",
                        help="dfw section id needed for create, read and delete")

    parser.set_defaults(func=_dfw_main)

def _dfw_main(args):
    if args.debug:
        debug = True
    else:
        debug = False

    config = ConfigParser.ConfigParser()
    assert config.read(args.ini), 'could not read config file {}'.format(args.ini)

    #if args.section_id:
    #    dfw_section_id = args.section_id
    #    dfw_section_id = str(dfw_section_id)
    #    uri_parameters={'sectionId': dfw_section_id}

    client_session = NsxClient(config.get('nsxraml', 'nsxraml_file'), config.get('nsxv', 'nsx_manager'),
                               config.get('nsxv', 'nsx_username'), config.get('nsxv', 'nsx_password'), debug=debug)

    try:
        command_selector = {
            'list_sections': _dfw_section_list_print,
            'read_section': _dfw_section_read_print,
            'list_rules':   _dfw_rule_list_print,
            }
        command_selector[args.command](client_session, verbose=args.verbose, dfw_section_id=args.section_id)


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