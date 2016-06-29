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

    if type(l2_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l2_dfw_sections),dict.values(l2_dfw_sections))
        l2_dfw_sections = list()
        l2_dfw_sections.append(dict(keys_and_values))

    if type(l3_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3_dfw_sections),dict.values(l3_dfw_sections))
        l3_dfw_sections = list()
        l3_dfw_sections.append(dict(keys_and_values))

    if type(l3r_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3r_dfw_sections),dict.values(l3r_dfw_sections))
        l3r_dfw_sections = list()
        l3r_dfw_sections.append(dict(keys_and_values))

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



def dfw_section_delete(client_session, section_id):
    """
    This function delete a section given its id
    :param client_session: An instance of an NsxClient Session
    :param section_name: The id of the section that must be deleted
    :return returns
            - A table containing these information: Return Code (True/False), Section ID, Section Name, Section Type
            - ( verbose option ) A list containing a single list which elements are Return Code (True/False),
              Section ID, Section Name, Section Type

            If there is no matching list
                - Return Code is set to False
                - Section ID is set to the value passed as input parameter
                - Section Name is set to "---"
                - Section Type is set to "---"
    """
    l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
    #print l2_section_list
    #print l3_section_list
    #print l3r_section_list
    #return
    dfw_section_id = str(section_id)
    result = list()

    for i, val in enumerate(l3_section_list):
        if dfw_section_id == str(val[1]):
            client_session.delete('dfwL3SectionId', uri_parameters={'sectionId': dfw_section_id})
            result = [["True", dfw_section_id, str(val[0]), str(val[-1])]]
            return result

    for i, val in enumerate(l2_section_list):
        if dfw_section_id == str(val[1]):
            client_session.delete('dfwL2SectionId', uri_parameters={'sectionId': dfw_section_id})
            result = [["True", dfw_section_id, str(val[0]), str(val[-1])]]
            return result

    for i, val in enumerate(l3r_section_list):
        if dfw_section_id == str(val[1]):
            client_session.delete('section', uri_parameters={'section': dfw_section_id})
            result = [["True", dfw_section_id, str(val[0]), str(val[-1])]]
            return result

    result = [["False", dfw_section_id, "---", "---"]]
    return result

def _dfw_section_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_section_id']):
        print ('Mandatory parameters missing: [-sid SECTION ID]')
        return None
    section_id = kwargs['dfw_section_id']
    result = dfw_section_delete(client_session, section_id)

    if kwargs['verbose']:
        print result
    else:
        print tabulate(result, headers=["Return Code", "Section ID", "Section Name", "Section Type"], tablefmt="psql")



def dfw_rule_delete(client_session, rule_id):
    """
    TBD
    This function delete a section given its id
    :param client_session: An instance of an NsxClient Session
    :param section_name: The id of the section that must be deleted
    :return returns
            - A table containing these information: Return Code (True/False), Section ID, Section Name, Section Type
            - ( verbose option ) A list containing a single list which elements are Return Code (True/False),
              Section ID, Section Name, Section Type

            If there is no matching list
                - Return Code is set to False
                - Section ID is set to the value passed as input parameter
                - Section Name is set to "---"
                - Section Type is set to "---"
    """
    l2_rule_list, l3_rule_list, l3r_rule_list = dfw_rule_list(client_session)
    #print l2_rule_list
    #print l3_rule_list
    #print l3r_rule_list
    #return
    dfw_rule_id = str(rule_id)

    for i, val in enumerate(l3_rule_list):
        if dfw_rule_id == str(val[0]):
            dfw_section_id = str(val[-1])
            section_list, dfwL3_section_details = dfw_section_read(client_session, dfw_section_id)
            etag = str(section_list[0][3])
            client_session.delete('dfwL3Rule', uri_parameters={'ruleId': dfw_rule_id, 'sectionId': dfw_section_id },
                                  additional_headers={'If-match': etag})
            result = [["True", dfw_rule_id, str(val[1]), str(val[-2]), str(val[-1])]]
            return result

    for i, val in enumerate(l2_rule_list):
        if dfw_rule_id == str(val[0]):
            dfw_section_id = str(val[-1])
            section_list, dfwL2_section_details = dfw_section_read(client_session, dfw_section_id)
            etag = str(section_list[0][3])
            client_session.delete('dfwL2Rule', uri_parameters={'ruleId': dfw_rule_id, 'sectionId': dfw_section_id},
                                  additional_headers={'If-match': etag})
            result = [["True", dfw_rule_id, str(val[1]), str(val[-2]), str(val[-1])]]
            return result

    for i, val in enumerate(l3r_rule_list):
        if dfw_rule_id == str(val[0]):
            dfw_section_id = str(val[-1])
            section_list, dfwL3r_section_details = dfw_section_read(client_session, dfw_section_id)
            etag = str(section_list[0][3])
            client_session.delete('rule', uri_parameters={'ruleID': dfw_rule_id, 'section': dfw_section_id})
            result = [["True", dfw_rule_id, str(val[1]), str(val[-2]), str(val[-1])]]
            return result

    result = [["False", dfw_rule_id, "---", "---", "---"]]
    return result

def _dfw_rule_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    rule_id = kwargs['dfw_rule_id']
    result = dfw_rule_delete(client_session, rule_id)

    if kwargs['verbose']:
        print result
    else:
        print tabulate(result, headers=["Return Code", "Rule ID", "Rule Name", "Applied-To", "Section ID"],
                       tablefmt="psql")



def dfw_section_id_read(client_session, dfw_section_name):
    """
    This function returns the section(s) ID(s) given a section name
    :param client_session: An instance of an NsxClient Session
    :param section_name: The name ( case sensitive ) of the section for which the ID is wanted
    :return returns
            - A list of dictionaries. Each dictionary contains the type and the id of each section with named as
              specified by the input parameter. If no such section exist, the list contain a single dictionary with
              {'Type': 0, 'Id': 0}
    """
    l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
    dfw_section_id = list()
    print dfw_section_id
    dfw_section_name = str(dfw_section_name)

    for i,val in enumerate(l3_section_list):
        if str(val[0]) == dfw_section_name:
            dfw_section_id.append({'Type': str(val[2]), 'Id': int(val[1])})

    for i,val in enumerate(l3r_section_list):
        if str(val[0]) == dfw_section_name:
            dfw_section_id.append({'Type': str(val[2]), 'Id': int(val[1])})

    for i,val in enumerate(l2_section_list):
        if str(val[0]) == dfw_section_name:
            dfw_section_id.append({'Type': str(val[2]), 'Id': int(val[1])})

    if len(dfw_section_id) == 0:
        dfw_section_id.append({'Type': 0, 'Id': 0})
    return dfw_section_id

def _dfw_section_id_read_print(client_session, **kwargs):

    if not (kwargs['dfw_section_name']):
        print ('Mandatory parameters missing: [-sname SECTION NAME]')
        return None
    dfw_section_name = str(kwargs['dfw_section_name'])
    dfw_section_id = dfw_section_id_read(client_session, dfw_section_name)
    print dfw_section_id



def dfw_rule_id_read(client_session, dfw_section_id, dfw_rule_name):
    """
    This function returns the rule(s) ID(s) given a section id and a rule name
    :param client_session: An instance of an NsxClient Session
    :param rule_name: The name ( case sensitive ) of the rule for which the ID is/are wanted. If rhe name includes
                      includes spaces, enclose it between ""
    :param section:id: The id of the section where the rule must be searched
    :return returns
            - A dictionary with the rule name as the key and a list as a value. The list contains all the matching
              rules id(s). For example {'RULE_ONE': [1013, 1012]}. If no matching rule exist, an empty dictionary is
              returned
    """

    l2_rule_list, l3_rule_list, l3r_rule_list = dfw_rule_list(client_session)

    print l2_rule_list
    print l3_rule_list
    print l3r_rule_list

    list_names = list()
    list_ids = list()
    dfw_rule_name = str(dfw_rule_name)
    #dfw_rule_name = dfw_rule_name.strip()
    dfw_section_id = str(dfw_section_id)

    for i, val in enumerate(l2_rule_list):
        if (dfw_rule_name == val[1]) and (dfw_section_id == val[-1]):
            list_names.append(dfw_rule_name)
            list_ids.append(int(val[0]))

    for i, val in enumerate(l3_rule_list):
        if (dfw_rule_name == val[1]) and (dfw_section_id == val[-1]):
            list_names.append(dfw_rule_name)
            list_ids.append(int(val[0]))

    for i, val in enumerate(l3r_rule_list):
        if (dfw_rule_name == val[1]) and (dfw_section_id == val[-1]):
            list_names.append(dfw_rule_name)
            list_ids.append(int(val[0]))

    dfw_rule_id = dict.fromkeys(list_names, list_ids)
    return dfw_rule_id

def _dfw_rule_id_read_print(client_session, **kwargs):

    if not (kwargs['dfw_rule_name']):
        print ('Mandatory parameters missing: [-rname RULE NAME (use "" if name includes spaces)]')
        return None
    if not (kwargs['dfw_section_id']):
        print ('Mandatory parameters missing: [-sid SECTION ID]')
        return None
    dfw_section_id = str(kwargs['dfw_section_id'])
    dfw_rule_name = str(kwargs['dfw_rule_name'])

    dfw_rule_id = dfw_rule_id_read(client_session, dfw_section_id, dfw_rule_name)
    print dfw_rule_id



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

    if type(l2_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l2_dfw_sections),dict.values(l2_dfw_sections))
        l2_dfw_sections = list()
        l2_dfw_sections.append(dict(keys_and_values))

    if type(l3_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3_dfw_sections),dict.values(l3_dfw_sections))
        l3_dfw_sections = list()
        l3_dfw_sections.append(dict(keys_and_values))
    #print ' l3 section '
    #print l3_dfw_sections

    if type(l3r_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3r_dfw_sections),dict.values(l3r_dfw_sections))
        l3r_dfw_sections = list()
        l3r_dfw_sections.append(dict(keys_and_values))
    #print ' l3r section '
    #print l3r_dfw_sections

    for i, val in enumerate(l2_dfw_sections):
        if 'rule' not in val:
            del l2_dfw_sections[i]
    if len(l2_dfw_sections) > 0:
        if 'rule' in l2_dfw_sections[0]:
            rule_list = list()
            for sptr in l2_dfw_sections:
                section_rules = client_session.normalize_list_return(sptr['rule'])
                l2_rule_list = dfw_rule_list_helper(client_session, section_rules, rule_list)
    else:
        l2_rule_list = []


    for i, val in enumerate(l3_dfw_sections):
        if 'rule' not in val:
            del l3_dfw_sections[i]
    if len(l3_dfw_sections) > 0:
        if 'rule' in l3_dfw_sections[0]:
            rule_list = list()
            for sptr in l3_dfw_sections:
                section_rules = client_session.normalize_list_return(sptr['rule'])
                l3_rule_list = dfw_rule_list_helper(client_session, section_rules, rule_list)
    else:
        l3_rule_list = []


    for i, val in enumerate(l3r_dfw_sections):
        if 'rule' not in val:
            del l3r_dfw_sections[i]
    if len(l3r_dfw_sections) > 0:
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



def dfw_rule_read(client_session, rule_id):
    """
    This funtions retrieves details of a dfw rule given its id
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The ID of the dfw rule to retrieve
    :return: returns
            - tabular view of the dfw rule
            - ( verbose option ) a list containing the dfw rule information: ID(Rule)- Name(Rule)- Source- Destination-
              Services- Action - Direction- Pktytpe- AppliedTo- ID(section)
    """
    rule_list = dfw_rule_list(client_session)
    rule = list()
    #print ''
    #print rule_list
    #print ''
    for sectionptr in rule_list:
        for ruleptr in sectionptr:
            if ruleptr[0] == str(rule_id):
                rule.append(ruleptr)
                #for data in ruleptr:
                    #rule.append(data)
    return rule

def _dfw_rule_read_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    rule_id = kwargs['dfw_rule_id']
    rule = dfw_rule_read(client_session, rule_id)
    if kwargs['verbose']:
        print rule
    else:
        print tabulate(rule, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                              "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")



def dfw_section_read(client_session, dfw_section_id):
    """
    This funtions retrieves details of a dfw section given its id
    :param client_session: An instance of an NsxClient Session
    :param dfw_section_id: The ID of the dfw section to retrieve details from
    :return: returns
            - a tabular view of the section with the following information: Name, Section id, Section type, Etag
            - ( verbose option ) a dictionary containing all sections's details
    """
    section_list = []
    dfw_section_id = str(dfw_section_id)
    uri_parameters={'sectionId': dfw_section_id}

    dfwL3_section_details = dict(client_session.read('dfwL3SectionId', uri_parameters))
    #return dfwL3_section_details
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
        print dfwL3_section_details['body']
    else:
        print tabulate(section_list, headers=["Name", "ID", "Type", "Etag"], tablefmt="psql")



def contruct_parser(subparsers):
    parser = subparsers.add_parser('dfw', description="Functions for distributed firewall",
                                   help="Functions for distributed firewall",
                                   formatter_class=RawTextHelpFormatter)

    parser.add_argument("command", help="""
    list_sections:   return a list of all distributed firewall's sections
    read_section:    return the details of a dfw section given its id
    read_section_id: return the id of a section given its name (case sensitive)
    list_rules:      return a list of all distributed firewall's rules
    read_rule:       return the details of a dfw rule given its id
    read_rule_id:    return the id of a rule given its name and the id of the section to which it belongs
    delete_section:  delete a section given its id
    delete_rule:     delete a rule given its id
    """)

    parser.add_argument("-sid",
                        "--dfw_section_id",
                        help="dfw section id needed for create, read and delete operations")
    parser.add_argument("-rid",
                        "--dfw_rule_id",
                        help="dfw rule id needed for create, read and delete operations")
    parser.add_argument("-sname",
                        "--dfw_section_name",
                        help="dfw section name")
    parser.add_argument("-rname",
                        "--dfw_rule_name",
                        help="dfw rule name")



    parser.set_defaults(func=_dfw_main)

def _dfw_main(args):
    if args.debug:
        debug = True
    else:
        debug = False

    config = ConfigParser.ConfigParser()
    assert config.read(args.ini), 'could not read config file {}'.format(args.ini)

    client_session = NsxClient(config.get('nsxraml', 'nsxraml_file'), config.get('nsxv', 'nsx_manager'),
                               config.get('nsxv', 'nsx_username'), config.get('nsxv', 'nsx_password'), debug=debug)

    try:
        command_selector = {
            'list_sections': _dfw_section_list_print,
            'read_section': _dfw_section_read_print,
            'list_rules': _dfw_rule_list_print,
            'read_rule': _dfw_rule_read_print,
            'read_section_id': _dfw_section_id_read_print,
            'read_rule_id': _dfw_rule_id_read_print,
            'delete_section': _dfw_section_delete_print,
            'delete_rule': _dfw_rule_delete_print,
            }
        command_selector[args.command](client_session, verbose=args.verbose, dfw_section_id=args.dfw_section_id,
                                       dfw_rule_id=args.dfw_rule_id, dfw_section_name=args.dfw_section_name,
                                       dfw_rule_name=args.dfw_rule_name)


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