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
from argparse import RawTextHelpFormatter
from tabulate import tabulate
from nsxramlclient.client import NsxClient
from pkg_resources import resource_filename
from libutils import dfw_rule_list_helper
from libutils import connect_to_vc
from libutils import nametovalue

__author__ = 'Emanuele Mazza'


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

    if str(all_dfw_sections['layer2Sections']) != 'None':
        l2_dfw_sections = all_dfw_sections['layer2Sections']['section']
    else:
        l2_dfw_sections = list()

    if str(all_dfw_sections['layer2Sections']) != 'None':
        l3r_dfw_sections = all_dfw_sections['layer3RedirectSections']['section']
    else:
        l3r_dfw_sections = list()

    if str(all_dfw_sections['layer3Sections']) != 'None':
        l3_dfw_sections = all_dfw_sections['layer3Sections']['section']
    else:
        l3_dfw_sections = list()

    l2_section_list = [['---', '---', '---']]
    l3r_section_list = [['---', '---', '---']]
    l3_section_list = [['---', '---', '---']]

    if type(l2_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l2_dfw_sections), dict.values(l2_dfw_sections))
        l2_dfw_sections = list()
        l2_dfw_sections.append(dict(keys_and_values))

    if type(l3_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3_dfw_sections), dict.values(l3_dfw_sections))
        l3_dfw_sections = list()
        l3_dfw_sections.append(dict(keys_and_values))

    if type(l3r_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3r_dfw_sections), dict.values(l3r_dfw_sections))
        l3r_dfw_sections = list()
        l3r_dfw_sections.append(dict(keys_and_values))

    if len(l2_dfw_sections) != 0:
        l2_section_list = list()
        for sl in l2_dfw_sections:
            try:
                section_name = sl['@name']
            except KeyError:
                section_name = '<empty name>'
            l2_section_list.append((section_name, sl['@id'], sl['@type']))

    if len(l3r_dfw_sections) != 0:
        l3r_section_list = list()
        for sl in l3r_dfw_sections:
            try:
                section_name = sl['@name']
            except KeyError:
                section_name = '<empty name>'
            l3r_section_list.append((section_name, sl['@id'], sl['@type']))

    if len(l3_dfw_sections) != 0:
        l3_section_list = list()
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
    :param section_id: The id of the section that must be deleted
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

    dfw_section_id = str(section_id)

    for i, val in enumerate(l3_section_list):
        if dfw_section_id == str(val[1]) and str(val[0]) != 'Default Section Layer3':
            client_session.delete('dfwL3SectionId', uri_parameters={'sectionId': dfw_section_id})
            result = [["True", dfw_section_id, str(val[0]), str(val[-1])]]
            return result
        if dfw_section_id == str(val[1]) and str(val[0]) == 'Default Section Layer3':
            result = [["False-Delete Default Section is not allowed", dfw_section_id, "---", "---"]]
            return result

    for i, val in enumerate(l2_section_list):
        if dfw_section_id == str(val[1]) and str(val[0]) != 'Default Section Layer2':
            client_session.delete('dfwL2SectionId', uri_parameters={'sectionId': dfw_section_id})
            result = [["True", dfw_section_id, str(val[0]), str(val[-1])]]
            return result
        if dfw_section_id == str(val[1]) and str(val[0]) == 'Default Section Layer2':
            result = [["False-Delete Default Section is not allowed", dfw_section_id, "---", "---"]]
            return result

    for i, val in enumerate(l3r_section_list):
        if dfw_section_id == str(val[1]) and str(val[0]) != 'Default Section':
            client_session.delete('section', uri_parameters={'section': dfw_section_id})
            result = [["True", dfw_section_id, str(val[0]), str(val[-1])]]
            return result
        if dfw_section_id == str(val[1]) and str(val[0]) == 'Default Section':
            result = [["False-Delete Default Section is not allowed", dfw_section_id, "---", "---"]]
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
    This function delete a dfw rule given its id
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The id of the rule that must be deleted
    :return returns
            - A table containing these information: Return Code (True/False), Rule ID, Rule Name, Applied-To, Section ID
            - ( verbose option ) A list containing a single list which elements are Return Code (True/False),
              Rule ID, Rule Name, Applied-To, Section ID

            If there is no matching rule
                - Return Code is set to False
                - Rule ID is set to the value passed as input parameter
                - All other returned parameters are set to "---"
    """
    l2_rule_list, l3_rule_list, l3r_rule_list = dfw_rule_list(client_session)
    dfw_rule_id = str(rule_id)

    for i, val in enumerate(l3_rule_list):
        if dfw_rule_id == str(val[0]) and str(val[1]) != 'Default Rule':
            dfw_section_id = str(val[-1])
            section_list, dfwL3_section_details = dfw_section_read(client_session, dfw_section_id)
            etag = str(section_list[0][3])
            client_session.delete('dfwL3Rule', uri_parameters={'ruleId': dfw_rule_id, 'sectionId': dfw_section_id},
                                  additional_headers={'If-match': etag})
            result = [["True", dfw_rule_id, str(val[1]), str(val[-2]), str(val[-1])]]
            return result
        else:
            result = [["False-Delete Default Rule is not allowed", dfw_rule_id, "---", "---", "---"]]
            return result

    for i, val in enumerate(l2_rule_list):
        if dfw_rule_id == str(val[0]) and str(val[1]) != 'Default Rule':
            dfw_section_id = str(val[-1])
            section_list, dfwL2_section_details = dfw_section_read(client_session, dfw_section_id)
            etag = str(section_list[0][3])
            client_session.delete('dfwL2Rule', uri_parameters={'ruleId': dfw_rule_id, 'sectionId': dfw_section_id},
                                  additional_headers={'If-match': etag})
            result = [["True", dfw_rule_id, str(val[1]), str(val[-2]), str(val[-1])]]
            return result
        else:
            result = [["False-Delete Default Rule is not allowed", dfw_rule_id, "---", "---", "---"]]
            return result

    for i, val in enumerate(l3r_rule_list):
        if dfw_rule_id == str(val[0]) and str(val[1]) != 'Default Rule':
            dfw_section_id = str(val[-1])
            section_list, dfwL3r_section_details = dfw_section_read(client_session, dfw_section_id)
            etag = str(section_list[0][3])
            client_session.delete('rule', uri_parameters={'ruleID': dfw_rule_id, 'section': dfw_section_id})
            result = [["True", dfw_rule_id, str(val[1]), str(val[-2]), str(val[-1])]]
            return result
        else:
            result = [["False-Delete Default Rule is not allowed", dfw_rule_id, "---", "---", "---"]]
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
    :param dfw_section_name: The name ( case sensitive ) of the section for which the ID is wanted
    :return returns
            - A list of dictionaries. Each dictionary contains the type and the id of each section with named as
              specified by the input parameter. If no such section exist, the list contain a single dictionary with
              {'Type': 0, 'Id': 0}
    """
    l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
    dfw_section_id = list()
    dfw_section_name = str(dfw_section_name)

    for i, val in enumerate(l3_section_list):
        if str(val[0]) == dfw_section_name:
            dfw_section_id.append({'Type': str(val[2]), 'Id': int(val[1])})

    for i, val in enumerate(l3r_section_list):
        if str(val[0]) == dfw_section_name:
            dfw_section_id.append({'Type': str(val[2]), 'Id': int(val[1])})

    for i, val in enumerate(l2_section_list):
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

    if kwargs['verbose']:
        print dfw_section_id
    else:
        dfw_section_id_csv = ",".join([str(section['Id']) for section in dfw_section_id])
        print dfw_section_id_csv

def dfw_rule_id_read(client_session, dfw_section_id, dfw_rule_name):
    """
    This function returns the rule(s) ID(s) given a section id and a rule name
    :param client_session: An instance of an NsxClient Session
    :param dfw_rule_name: The name ( case sensitive ) of the rule for which the ID is/are wanted. If rhe name includes
                      includes spaces, enclose it between ""
    :param dfw_section_id: The id of the section where the rule must be searched
    :return returns
            - A dictionary with the rule name as the key and a list as a value. The list contains all the matching
              rules id(s). For example {'RULE_ONE': [1013, 1012]}. If no matching rule exist, an empty dictionary is
              returned
    """

    l2_rule_list, l3_rule_list, l3r_rule_list = dfw_rule_list(client_session)

    list_names = list()
    list_ids = list()
    dfw_rule_name = str(dfw_rule_name)
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

    if kwargs['verbose']:
        print dfw_rule_id
    else:
        try:
            dfw_rule_ids_str = [str(ruleid) for ruleid in dfw_rule_id[dfw_rule_name]]
            dfw_rule_id_csv = ",".join(dfw_rule_ids_str)
            print tabulate([(dfw_rule_name, dfw_rule_id_csv)], headers=["Rule Name", "Rule IDs"], tablefmt="psql")
        except KeyError:
            print 'Rule name {} not found in section Id {}'.format(kwargs['dfw_rule_name'], kwargs['dfw_section_id'])


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

    if str(all_dfw_sections[0]['layer3Sections']) != 'None':
        l3_dfw_sections = all_dfw_sections[0]['layer3Sections']['section']
    else:
        l3_dfw_sections = list()

    if str(all_dfw_sections[0]['layer2Sections']) != 'None':
        l2_dfw_sections = all_dfw_sections[0]['layer2Sections']['section']
    else:
        l2_dfw_sections = list()

    if str(all_dfw_sections[0]['layer3RedirectSections']) != 'None':
        l3r_dfw_sections = all_dfw_sections[0]['layer3RedirectSections']['section']
    else:
        l3r_dfw_sections = list()

    if type(l2_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l2_dfw_sections), dict.values(l2_dfw_sections))
        l2_dfw_sections = list()
        l2_dfw_sections.append(dict(keys_and_values))

    if type(l3_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3_dfw_sections), dict.values(l3_dfw_sections))
        l3_dfw_sections = list()
        l3_dfw_sections.append(dict(keys_and_values))

    if type(l3r_dfw_sections) is not list:
        keys_and_values = zip(dict.keys(l3r_dfw_sections), dict.values(l3r_dfw_sections))
        l3r_dfw_sections = list()
        l3r_dfw_sections.append(dict(keys_and_values))

    l2_temp = list()
    l2_rule_list = list()
    if len(l2_dfw_sections) != 0:
        for i, val in enumerate(l2_dfw_sections):
            if 'rule' in val:
                l2_temp.append(l2_dfw_sections[i])
        l2_dfw_sections = l2_temp
        if len(l2_dfw_sections) > 0:
            if 'rule' in l2_dfw_sections[0]:
                rule_list = list()
                for sptr in l2_dfw_sections:
                    section_rules = client_session.normalize_list_return(sptr['rule'])
                    l2_rule_list = dfw_rule_list_helper(client_session, section_rules, rule_list)
        else:
            l2_rule_list = []

    l3_temp = list()
    l3_rule_list = list()
    if len(l3_dfw_sections) != 0:
        for i, val in enumerate(l3_dfw_sections):
            if 'rule' in val:
                l3_temp.append(l3_dfw_sections[i])
        l3_dfw_sections = l3_temp
        if len(l3_dfw_sections) > 0:
            if 'rule' in l3_dfw_sections[0]:
                rule_list = list()
                for sptr in l3_dfw_sections:
                    section_rules = client_session.normalize_list_return(sptr['rule'])
                    l3_rule_list = dfw_rule_list_helper(client_session, section_rules, rule_list)
        else:
            l3_rule_list = []

    l3r_temp = list()
    l3r_rule_list = list()
    if len(l3r_dfw_sections) != 0:
        for i, val in enumerate(l3r_dfw_sections):
            if 'rule' in val:
                l3r_temp.append(l3r_dfw_sections[i])
        l3r_dfw_sections = l3r_temp
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
    This function retrieves details of a dfw rule given its id
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The ID of the dfw rule to retrieve
    :return: returns
            - tabular view of the dfw rule
            - ( verbose option ) a list containing the dfw rule information: ID(Rule)- Name(Rule)- Source- Destination-
              Services- Action - Direction- Pktytpe- AppliedTo- ID(section)
    """
    rule_list = dfw_rule_list(client_session)
    rule = list()

    for sectionptr in rule_list:
        for ruleptr in sectionptr:
            if ruleptr[0] == str(rule_id):
                rule.append(ruleptr)
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


def dfw_rule_source_delete(client_session, rule_id, source):
    """
    This function delete one of the sources of a dfw rule given the rule id and the source to be deleted
    If two or more sources have the same name, the function will delete all of them
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The ID of the dfw rule to retrieve
    :param source: The source of the dfw rule to be deleted. If the source name contains any space, then it must be
                   enclosed in double quotes (like "VM Network")
    :return: returns
            - tabular view of the dfw rule after the deletion process has been performed
            - ( verbose option ) a list containing a list with the following dfw rule informations after the deletion
              process has been performed: ID(Rule)- Name(Rule)- Source- Destination- Services- Action - Direction-
              Pktytpe- AppliedTo- ID(section)
    """

    source = str(source)
    rule = dfw_rule_read(client_session, rule_id)

    if len(rule) == 0:
        # It means a rule with id = rule_id does not exist
        result = [[rule_id, "---", source, "---", "---", "---", "---", "---", "---", "---"]]
        return result

    # Get the rule data structure that will be modified and then piped into the update function
    section_list = dfw_section_list(client_session)
    sections = [section_list[0], section_list[1], section_list[2]]
    section_id = rule[0][-1]

    rule_type_selector = ''
    for scan in sections:
        for val in scan:
            if val[1] == section_id:
                rule_type_selector = val[2]

    if rule_type_selector == '':
        print 'ERROR: RULE TYPE SELECTOR CANNOT BE EMPTY - ABORT !'
        return
    if rule_type_selector == 'LAYER2':
        rule_type = 'dfwL2Rule'
    elif rule_type_selector == 'LAYER3':
        rule_type = 'dfwL3Rule'
    else:
        rule_type = 'rule'

    rule_schema = client_session.read(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id})
    rule_etag = rule_schema.items()[-1][1]

    if 'sources' not in rule_schema.items()[1][1]['rule']:
        # It means the only source is "any" and it cannot be deleted short of deleting the whole rule
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['sources']['source']) == list:
        # It means there are more than one sources, each one with his own dict
        sources_list = rule_schema.items()[1][1]['rule']['sources']['source']
        for i, val in enumerate(sources_list):
            if val['type'] == 'Ipv4Address' and val['value'] == source or 'name' in val and val['name'] == source:
                del rule_schema.items()[1][1]['rule']['sources']['source'][i]

        # The order dict "rule_schema" must be parsed to find the dict that will be piped into the update function
        rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                     request_body_dict=rule_schema.items()[1][1],
                                     additional_headers={'If-match': rule_etag})
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['sources']['source']) == dict:
        # It means there is just one explicit source with his dict
        source_dict = rule_schema.items()[1][1]['rule']['sources']['source']
        if source_dict['type'] == 'Ipv4Address' and source_dict['value'] == source or \
                                  'name' in dict.keys(source_dict) and source_dict['name'] == source:
            del rule_schema.items()[1][1]['rule']['sources']
            rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                         request_body_dict=rule_schema.items()[1][1],
                                         additional_headers={'If-match': rule_etag})

        rule = dfw_rule_read(client_session, rule_id)
        return rule


def _dfw_rule_source_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    if not (kwargs['dfw_rule_source']):
        print ('Mandatory parameters missing: [-src RULE SOURCE]')
        return None
    rule_id = kwargs['dfw_rule_id']
    source = kwargs['dfw_rule_source']
    rule = dfw_rule_source_delete(client_session, rule_id, source)
    if kwargs['verbose']:
        print rule
    else:
        print tabulate(rule, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                      "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")


def dfw_rule_destination_delete(client_session, rule_id, destination):
    """
    This function delete one of the destinations of a dfw rule given the rule id and the destination to be deleted.
    If two or more destinations have the same name, the function will delete all of them
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The ID of the dfw rule to retrieve
    :param destination: The destination of the dfw rule to be deleted. If the destination name contains any space, then
                        it must be enclosed in double quotes (like "VM Network")
    :return: returns
            - tabular view of the dfw rule after the deletion process has been performed
            - ( verbose option ) a list containing a list with the following dfw rule informations after the deletion
              process has been performed: ID(Rule)- Name(Rule)- Source- Destination- Services- Action - Direction-
              Pktytpe- AppliedTo- ID(section)
    """

    destination = str(destination)
    rule = dfw_rule_read(client_session, rule_id)

    if len(rule) == 0:
        # It means a rule with id = rule_id does not exist
        result = [[rule_id, "---", "---", destination, "---", "---", "---", "---", "---", "---"]]
        return result

    # Get the rule data structure that will be modified and then piped into the update function
    section_list = dfw_section_list(client_session)
    sections = [section_list[0], section_list[1], section_list[2]]
    section_id = rule[0][-1]

    rule_type_selector = ''
    for scan in sections:
        for val in scan:
            if val[1] == section_id:
                rule_type_selector = val[2]

    if rule_type_selector == '':
        print 'ERROR: RULE TYPE SELECTOR CANNOT BE EMPTY - ABORT !'
        return
    if rule_type_selector == 'LAYER2':
        rule_type = 'dfwL2Rule'
    elif rule_type_selector == 'LAYER3':
        rule_type = 'dfwL3Rule'
    else:
        rule_type = 'rule'

    rule_schema = client_session.read(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id})
    rule_etag = rule_schema.items()[-1][1]

    if 'destinations' not in rule_schema.items()[1][1]['rule']:
        # It means the only destination is "any" and it cannot be deleted short of deleting the whole rule
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['destinations']['destination']) == list:
        # It means there are more than one destinations, each one with his own dict
        destination_list = rule_schema.items()[1][1]['rule']['destinations']['destination']
        for i, val in enumerate(destination_list):
            if val['type'] == 'Ipv4Address' and val['value'] == destination or \
                                    'name' in val and val['name'] == destination:
                del rule_schema.items()[1][1]['rule']['destinations']['destination'][i]

        # The order dict "rule_schema" must be parsed to find the dict that will be piped into the update function
        rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                     request_body_dict=rule_schema.items()[1][1],
                                     additional_headers={'If-match': rule_etag})
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['destinations']['destination']) == dict:
        # It means there is just one explicit destination with his dict
        destination_dict = rule_schema.items()[1][1]['rule']['destinations']['destination']
        if destination_dict['type'] == 'Ipv4Address' and destination_dict['value'] == destination or \
                                       'name' in dict.keys(destination_dict) and \
                                       destination_dict['name'] == destination:
            del rule_schema.items()[1][1]['rule']['destinations']
            rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                         request_body_dict=rule_schema.items()[1][1],
                                         additional_headers={'If-match': rule_etag})

        rule = dfw_rule_read(client_session, rule_id)
        return rule


def _dfw_rule_destination_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    if not (kwargs['dfw_rule_destination']):
        print ('Mandatory parameters missing: [-dst RULE DESTINATION]')
        return None
    rule_id = kwargs['dfw_rule_id']
    destination = kwargs['dfw_rule_destination']
    rule = dfw_rule_destination_delete(client_session, rule_id, destination)
    if kwargs['verbose']:
        print rule
    else:
        print tabulate(rule, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                      "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")


def dfw_rule_create(client_session, vccontent, section_id, rule_name, rule_direction, rule_pktype, rule_disabled,
                    rule_action, rule_applyto, rule_source_type, rule_source_name, rule_source_value,
                    rule_source_excluded, rule_destination_type, rule_destination_name, rule_destination_value,
                    rule_destination_excluded, rule_service_protocolname, rule_service_destport,
                    rule_service_srcport, rule_service_name, rule_note, rule_tag, rule_logged):

    # TODO: complete the description

    API_TYPES = {'dc': 'Datacenter', 'ipset': 'IPSet', 'macset': 'MACSet', 'ls': 'VirtualWire',
                 'secgroup': 'SecurityGroup', 'host': 'HostSystem', 'vm':'VirtualMachine',
                 'cluster': 'ClusterComputeResource', 'dportgroup': 'DistributedVirtualPortgroup',
                 'portgroup': 'Network', 'respool': 'ResourcePool', 'vapp': 'ResourcePool', 'vnic': 'VirtualMachine'}

    # Verify that in the target section a rule with the same name does not exist
    # Find the rule type from the target section

    l2_rule_list, l3_rule_list, l3r_rule_list = dfw_rule_list(client_session)

    section_list = dfw_section_list(client_session)
    sections = [section_list[0], section_list[1], section_list[2]]

    rule_type_selector = ''
    for scan in sections:
        for val in scan:
            if val[1] == section_id:
                rule_type_selector = val[2]

    if rule_type_selector == '':
        print 'ERROR: RULE TYPE SELECTOR CANNOT BE EMPTY - ABORT !'
        return

    if rule_type_selector == 'LAYER2' or rule_type_selector == 'LAYER3':
        if rule_type_selector == 'LAYER2':
            for val in l2_rule_list:
                if val[1] == rule_name:
                    print 'RULE WITH SAME NAME EXIST ABORT'
                    return
            rule_type = 'dfwL2Rules'
            section_type = 'dfwL2SectionId'
            if rule_pktype != 'any':
                print ('For a L2 rule "any" is the only allowed value for parameter -pktype')
                return None
            if rule_action != 'allow' and rule_action != 'block':
                print ('For a L2 rule "allow/block" are the only allowed value for parameter -action')
                return None
            # For L2 rules where the GUI shows "block" the python data structure for the API call needs "deny"
            # At the cli level this must be hidden to avoid confusing the user with too many options for the same action
            if rule_action == 'block':
                rule_action = 'deny'
            if rule_applyto == 'ANY' or rule_applyto == 'ALL_EDGES':
                print ('For a L2 rule "any" and "edgegw" are not allowed values for parameter -appto')
                return None
            if rule_source_type == 'IPSet' or rule_destination_type == 'IPSet':
                print ('For a L2 rule "IPSET" is not an allowed value neither as source nor as destination')
                return None

        if rule_type_selector == 'LAYER3':
            for val in l3_rule_list:
                if val[1] == rule_name:
                    print 'RULE WITH SAME NAME EXIST ABORT'
                    return
            rule_type = 'dfwL3Rules'
            section_type = 'dfwL3SectionId'
        # The schema for L2rules is the same as for L3rules
        rule_schema = client_session.extract_resource_body_example('dfwL3Rules', 'create')
    else:
        for val in l3r_rule_list:
            if val[1] == rule_name:
                print 'RULE WITH SAME NAME EXIST ABORT'
                return
        rule_type = 'rules'
        section_type = 'section'
        rule_schema = client_session.extract_resource_body_example(rule_type, 'create')
        print 'L3 redirect rules are not supported in this version - No action will be performed on the system'
        return

    section = client_session.read(section_type, uri_parameters={'sectionId': section_id})
    section_etag = section.items()[-1][1]

    if rule_type != 'rules':
        # L3 or L2 rule
        # Mandatory values of a rule
        rule_schema['rule']['name'] = str(rule_name)
        # If appliedTo is 'ALL_EDGES' only inout is allowed
        rule_schema['rule']['direction'] = str(rule_direction)
        # If appliedTo is 'ALL_EDGES' only packetType any is allowed
        rule_schema['rule']['packetType'] = str(rule_pktype)
        rule_schema['rule']['@disabled'] = str(rule_disabled)
        rule_schema['rule']['action'] = str(rule_action)
        rule_schema['rule']['appliedToList']['appliedTo']['value'] = str(rule_applyto)

        # Optional values of a rule. I believe it's cleaner to set them anyway, even if to an empty value
        rule_schema['rule']['notes'] = rule_note
        # If appliedTo is 'ALL_EDGES' no tags are allowed
        rule_schema['rule']['tag'] = rule_tag
        rule_schema['rule']['@logged'] = rule_logged

        # Deleting all the three following sections will create the simplest any any any allow any rule
        #
        # If no source is specified the section needs to be deleted
        if (rule_source_value == '' and rule_source_type == '') \
                or (rule_source_name == '' and rule_source_type == ''):
            del rule_schema['rule']['sources']
        # Mandatory values of a source ( NB: source is an optional value )
        elif (rule_source_value != ''):
            rule_schema['rule']['sources']['source']['value'] = rule_source_value
            rule_schema['rule']['sources']['source']['type'] = API_TYPES[rule_source_type]
            # Optional values of a source ( if specified )
            if rule_source_excluded != '':
                rule_schema['rule']['sources']['@excluded'] = rule_source_excluded
        elif (rule_source_name != ''):
            # Code to map name to value
            rule_source_value = nametovalue(vccontent, client_session, rule_source_name, rule_source_type)
            if rule_source_value == '':
                print 'Matching Source Object ID not found - Abort - No operations have been performed on the system'
                return
            rule_schema['rule']['sources']['source']['value'] = rule_source_value
            rule_schema['rule']['sources']['source']['type'] = API_TYPES[rule_source_type]
            # Optional values of a source ( if specified )
            if rule_source_excluded != '':
                rule_schema['rule']['sources']['@excluded'] = rule_source_excluded

        # If no destination is specified the section needs to be deleted
        if (rule_destination_value == '' and rule_destination_type == '') \
                or (rule_destination_name == '' and rule_destination_type == ''):
            del rule_schema['rule']['destinations']
        # Mandatory values of a destination ( NB: destination is an optional value )
        elif (rule_destination_value != ''):
            rule_schema['rule']['destinations']['destination']['value'] = rule_destination_value
            #rule_schema['rule']['destinations']['destination']['type'] = rule_destination_type
            rule_schema['rule']['destinations']['destination']['type'] = API_TYPES[rule_destination_type]
            # Optional values of a destination ( if specified )
            if rule_destination_excluded != '':
                rule_schema['rule']['destinations']['@excluded'] = rule_destination_excluded
        elif (rule_destination_name != ''):
            # Code to map name to value
            rule_destination_value = nametovalue(vccontent, client_session, rule_destination_name,
                                                 rule_destination_type)
            if rule_destination_value == '':
                print 'Matching Destination Object ID not found - No operations have been performed on the system'
                return
            rule_schema['rule']['destinations']['destination']['value'] = rule_destination_value
            rule_schema['rule']['destinations']['destination']['type'] = API_TYPES[rule_destination_type]
            # Optional values of a destination ( if specified )
            if rule_destination_excluded != '':
                rule_schema['rule']['destinations']['@excluded'] = rule_destination_excluded

        # If no services are specified the section needs to be deleted
        if rule_service_protocolname == '' and rule_service_destport == '' and rule_service_name == '':
            del rule_schema['rule']['services']
        elif rule_service_protocolname != '' and rule_service_destport != '' and rule_service_name != '':
            print ('Service can be specified either via protocol/port or name')
            return
        elif rule_service_protocolname != '':
            # Mandatory values of a service specified via protocol ( NB: service is an optional value )
            rule_schema['rule']['services']['service']['protocolName'] = rule_service_protocolname
            if rule_service_destport != '':
                rule_schema['rule']['services']['service']['destinationPort'] = rule_service_destport
            # Optional values of a service specified via protocol ( if specified )
            if rule_service_srcport != '':
                rule_schema['rule']['services']['service']['sourcePort'] = rule_service_srcport
        elif rule_service_name != '':
            # Mandatory values of a service specified via application/application group (service is an optional value)
            rule_schema['rule']['services']['service']['value'] = ''
            services = client_session.read('servicesScope', uri_parameters={'scopeId': 'globalroot-0'})
            service = services.items()[1][1]['list']['application']
            for servicedict in service:
                if str(servicedict['name']) == rule_service_name:
                    rule_schema['rule']['services']['service']['value'] = str(servicedict['objectId'])
            if rule_schema['rule']['services']['service']['value'] == '':
                servicegroups = client_session.read('serviceGroups', uri_parameters={'scopeId': 'globalroot-0'})
                servicegrouplist = servicegroups.items()[1][1]['list']['applicationGroup']
                for servicegroupdict in servicegrouplist:
                    if str(servicegroupdict['name']) == rule_service_name:
                        rule_schema['rule']['services']['service']['value'] = str(servicegroupdict['objectId'])
            if rule_schema['rule']['services']['service']['value'] == '':
                print ('Invalid service specified')
                return

    try:
        rule = client_session.create(rule_type, uri_parameters={'sectionId': section_id}, request_body_dict=rule_schema,
                                 additional_headers={'If-match': section_etag})

        l2_rule_list, l3_rule_list, l3r_rule_list = dfw_rule_list(client_session)

        print '*** ETHERNET RULES ***'
        print tabulate(l2_rule_list, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                              "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")
        print ''
        print '*** LAYER 3 RULES ***'
        print tabulate(l3_rule_list, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                              "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")

    except:
        print("Unexpected error - No action have been performed on the system")
    return


def _dfw_rule_create_print(client_session, vccontent, **kwargs):

    if not (kwargs['dfw_section_id']):
        print ('Mandatory parameters missing: [-sid SECTION ID]')
        return None
    section_id = kwargs['dfw_section_id']

    if not (kwargs['dfw_rule_name']):
        print ('Mandatory parameters missing: [-rname RULE NAME]')
        return None
    rule_name = kwargs['dfw_rule_name']

    if not (kwargs['dfw_rule_applyto']):
        print ('Mandatory parameters missing: [-appto RULE APPLYTO VALUE]')
        return None
    if kwargs['dfw_rule_applyto'] == 'any':
        rule_applyto = 'ANY'
    elif kwargs['dfw_rule_applyto'] == 'dfw':
        rule_applyto = 'DISTRIBUTED_FIREWALL'
    elif kwargs['dfw_rule_applyto'] == 'edgegw':
        rule_applyto = 'ALL_EDGES'
    else:
        rule_applyto = kwargs['dfw_rule_applyto']

    if not (kwargs['dfw_rule_direction']):
        print ('Mandatory parameters missing: [-dir RULE DIRECTION]')
        return None
    if rule_applyto != 'ALL_EDGES' \
            and ((kwargs['dfw_rule_direction']) == 'inout' or (kwargs['dfw_rule_direction']) == 'in' or
                         (kwargs['dfw_rule_direction']) == 'out'):
        rule_direction = kwargs['dfw_rule_direction']
    elif rule_applyto == 'ALL_EDGES' and (kwargs['dfw_rule_direction']) == 'inout':
        rule_direction = kwargs['dfw_rule_direction']
    else:
        print ('Allowed values for -dir parameter are inout/in/out')
        print('If the rule is applied to all edge gateways, then "inout" is the only allowed value for parameter -dir')
        return None

    if not (kwargs['dfw_rule_pktype']):
        print ('Mandatory parameters missing: [-pktype RULE PACKET TYPE]')
        return None
    if rule_applyto != 'ALL_EDGES' \
            and ((kwargs['dfw_rule_pktype']) == 'any' or (kwargs['dfw_rule_pktype']) == 'ipv4' or
                         (kwargs['dfw_rule_pktype']) == 'ipv6'):
        rule_pktype = kwargs['dfw_rule_pktype']
    elif rule_applyto == 'ALL_EDGES' and (kwargs['dfw_rule_pktype']) == 'any':
        rule_pktype = kwargs['dfw_rule_pktype']
    else:
        print ('Allowed values for -pktype parameter are any/ipv6/ipv4')
        print ('For a L3 rules applied to all edge gateways "any" is the only allowed value for parameter -pktype')
        print ('For a L2 rule "any" is the only allowed value for parameter -pktype')
        return None

    if not (kwargs['dfw_rule_disabled']):
        print ('Mandatory parameters missing: [-disabled RULE DISABLED]')
        return None
    if (kwargs['dfw_rule_disabled']) == 'false' or (kwargs['dfw_rule_disabled']) == 'true':
        rule_disabled = kwargs['dfw_rule_disabled']
    else:
        print ('Allowed values for -disabled parameter are true/false')
        return None

    if not (kwargs['dfw_rule_action']):
        print ('Mandatory parameters missing: [-action RULE ACTION]')
        return None
    if (kwargs['dfw_rule_action']) == 'allow' or (kwargs['dfw_rule_action']) == 'block' \
            or (kwargs['dfw_rule_action']) == 'reject':
        rule_action = kwargs['dfw_rule_action']
    else:
        print ('For a L3 rule allowed values for -action parameter are allow/block/reject')
        print ('For a L2 rule allowed values for -action parameter are allow/block')
        return None

    if not (kwargs['dfw_rule_source_type']):
        rule_source_type = ''
    else:
        rule_source_type = kwargs['dfw_rule_source_type']

    if not (kwargs['dfw_rule_source_value']):
        rule_source_value = ''
    else:
        rule_source_value = kwargs['dfw_rule_source_value']

    if not (kwargs['dfw_rule_source_name']):
        rule_source_name = ''
    else:
        rule_source_name = kwargs['dfw_rule_source_name']

    if ((rule_source_value == '' and rule_source_name == '') and rule_source_type != '') \
            or rule_source_type == '':
        print ('Rule source parameters "type" and "value/name" must both be defined or not defined')
        return

    if not (kwargs['dfw_rule_source_excluded']):
        rule_source_excluded = ''
    elif (kwargs['dfw_rule_source_excluded']) != 'true' or (kwargs['dfw_rule_source_excluded']) != 'false':
        print ('Allowed values for rule source excluded parameter are "true" and "false"')
        return
    else:
        rule_source_excluded = kwargs['dfw_rule_source_excluded']

    if not (kwargs['dfw_rule_destination_type']):
        rule_destination_type = ''
    else:
        rule_destination_type = kwargs['dfw_rule_destination_type']

    if not (kwargs['dfw_rule_destination_name']):
        rule_destination_name = ''
    else:
        rule_destination_name = kwargs['dfw_rule_destination_name']

    if not (kwargs['dfw_rule_destination_value']):
        rule_destination_value = ''
    else:
        rule_destination_value = kwargs['dfw_rule_destination_value']

    if ((rule_destination_value == '' and rule_destination_name == '') and rule_destination_type != '') \
            or rule_destination_type == '':
        print ('Rule destination parameters "type" and "value/name" must both be defined or not defined')
        return

    if not (kwargs['dfw_rule_destination_excluded']):
        rule_destination_excluded = ''
    elif (kwargs['dfw_rule_destination_excluded']) != 'true' and (kwargs['dfw_rule_destination_excluded']) != 'false':
        print ('Allowed values for rule destination excluded parameter are "true" and "false"')
        return
    else:
        rule_destination_excluded = kwargs['dfw_rule_destination_excluded']

    if not (kwargs['dfw_rule_service_protocolname']):
        rule_service_protocolname = ''
    else:
        rule_service_protocolname = kwargs['dfw_rule_service_protocolname']

    if not (kwargs['dfw_rule_service_destport']):
        rule_service_destport = ''
    else:
        rule_service_destport = kwargs['dfw_rule_service_destport']

    if not (kwargs['dfw_rule_service_srcport']):
        rule_service_srcport = ''
    else:
        rule_service_srcport = kwargs['dfw_rule_service_srcport']

    if not (kwargs['dfw_rule_service_name']):
        rule_service_name = ''
    else:
        rule_service_name = kwargs['dfw_rule_service_name']

    if (rule_service_protocolname == '') and (rule_service_destport != ''):
        print ('Protocol name must be specified in the rule service definition')
        return
    if (rule_service_protocolname != '') and (rule_service_destport != '') and (rule_service_name != ''):
        print ('Rule service can be specified by either protocol/port or service name, but not both')
        return

    if rule_applyto != 'ALL_EDGES':
        if not (kwargs['dfw_rule_tag']):
            rule_tag = ''
        else:
            rule_tag = kwargs['dfw_rule_tag']
    elif rule_applyto == 'ALL_EDGES':
        # If appliedTo is 'ALL_EDGES' no tags are allowed
        rule_tag = ''
    else:
        rule_tag = ''

    if not (kwargs['dfw_rule_note']):
        rule_note = ''
    else:
        rule_note = kwargs['dfw_rule_note']

    if not (kwargs['dfw_rule_logged']):
        rule_logged = 'false'
    else:
        if kwargs['dfw_rule_logged'] == 'true' or kwargs['dfw_rule_logged'] == 'false':
            rule_logged = kwargs['dfw_rule_logged']
        else:
            print ('Allowed values for rule logging are "true" and "false"')
            return

    rule = dfw_rule_create(client_session, vccontent, section_id, rule_name, rule_direction, rule_pktype, rule_disabled,
                           rule_action, rule_applyto, rule_source_type, rule_source_name, rule_source_value,
                           rule_source_excluded, rule_destination_type, rule_destination_name, rule_destination_value,
                           rule_destination_excluded, rule_service_protocolname, rule_service_destport,
                           rule_service_srcport, rule_service_name, rule_note, rule_tag, rule_logged)

    if kwargs['verbose']:
        print rule
    else:
        print tabulate(rule, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                      "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")


def dfw_rule_service_delete(client_session, rule_id, service):
    """
    This function delete one of the services of a dfw rule given the rule id and the service to be deleted.
    If two or more services have the same name, the function will delete all of them
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The ID of the dfw rule to retrieve
    :param service: The service of the dfw rule to be deleted. If the service name contains any space, then
                    it must be enclosed in double quotes (like "VM Network"). For TCP/UDP services the syntax is as
                    follows: Proto:SourcePort:DestinationPort ( example TCP:9090:any )
    :return: returns
            - tabular view of the dfw rule after the deletion process has been performed
            - ( verbose option ) a list containing a list with the following dfw rule informations after the deletion
              process has been performed: ID(Rule)- Name(Rule)- Source- Destination- Services- Action - Direction-
              Pktytpe- AppliedTo- ID(section)
    """

    service = str(service).split(':', 3)
    if len(service) == 1:
        service.append('')
    if len(service) == 2:
        service.append('')

    rule = dfw_rule_read(client_session, rule_id)

    if len(rule) == 0:
        # It means a rule with id = rule_id does not exist
        result = [[rule_id, "---", "---", "---", service, "---", "---", "---", "---", "---"]]
        return result

    # Get the rule data structure that will be modified and then piped into the update function
    section_list = dfw_section_list(client_session)
    sections = [section_list[0], section_list[1], section_list[2]]
    section_id = rule[0][-1]

    rule_type_selector = ''
    for scan in sections:
        for val in scan:
            if val[1] == section_id:
                rule_type_selector = val[2]

    if rule_type_selector == '':
        print 'ERROR: RULE TYPE SELECTOR CANNOT BE EMPTY - ABORT !'
        return
    if rule_type_selector == 'LAYER2':
        rule_type = 'dfwL2Rule'
    elif rule_type_selector == 'LAYER3':
        rule_type = 'dfwL3Rule'
    else:
        rule_type = 'rule'

    rule_schema = client_session.read(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id})
    rule_etag = rule_schema.items()[-1][1]

    if 'services' not in rule_schema.items()[1][1]['rule']:
        # It means the only service is "any" and it cannot be deleted short of deleting the whole rule
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['services']['service']) == list:
        # It means there are more than one services, each one with his own dict
        service_list = rule_schema.items()[1][1]['rule']['services']['service']
        for i, val in enumerate(service_list):
            if ('name' in val and val['name'] == service[0]) or ('sourcePort' not in val and service[1] == 'any'
            and 'destinationPort' not in val and service[2] == 'any' and 'protocolName' in val and
            val['protocolName'] == service[0]) or ('sourcePort' in val and val['sourcePort'] == service[1]
            and 'destinationPort' not in val and service[2] == 'any' and 'protocolName' in val
            and val['protocolName'] == service[0]) or ('sourcePort' in val and val['sourcePort'] == service[1]
            and 'destinationPort' in val and val['destinationPort'] == service[2] and 'protocolName' in val
            and val['protocolName'] == service[0]) or ('sourcePort' not in val and service[1] == 'any'
            and 'destinationPort' in val and val['destinationPort'] == service[2] and 'protocolName' in val and
            val['protocolName'] == service[0]):
                del rule_schema.items()[1][1]['rule']['services']['service'][i]

        # The order dict "rule_schema" must be parsed to find the dict that will be piped into the update function
        rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                     request_body_dict=rule_schema.items()[1][1],
                                     additional_headers={'If-match': rule_etag})
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['services']['service']) == dict:
        # It means there is just one explicit service with his dict
        service_dict = rule_schema.items()[1][1]['rule']['services']['service']
        val = service_dict

        if ('name' in val and val['name'] == service[0]) or ('sourcePort' not in val and service[1] == 'any'
        and 'destinationPort' not in val and service[2] == 'any' and 'protocolName' in val and
        val['protocolName'] == service[0]) or ('sourcePort' in val and val['sourcePort'] == service[1]
        and 'destinationPort' not in val and service[2] == 'any' and 'protocolName' in val
        and val['protocolName'] == service[0]) or ('sourcePort' in val and val['sourcePort'] == service[1]
        and 'destinationPort' in val and val['destinationPort'] == service[2] and 'protocolName' in val
        and val['protocolName'] == service[0]) or ('sourcePort' not in val and service[1] == 'any'
        and 'destinationPort' in val and val['destinationPort'] == service[2] and 'protocolName' in val and
        val['protocolName'] == service[0]):
            del rule_schema.items()[1][1]['rule']['services']
            rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                         request_body_dict=rule_schema.items()[1][1],
                                         additional_headers={'If-match': rule_etag})

        rule = dfw_rule_read(client_session, rule_id)
        return rule


def _dfw_rule_service_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    if not (kwargs['dfw_rule_service']):
        print ('Mandatory parameters missing: [-srv RULE SERVICE]')
        return None
    rule_id = kwargs['dfw_rule_id']
    service = kwargs['dfw_rule_service']
    rule = dfw_rule_service_delete(client_session, rule_id, service)
    if kwargs['verbose']:
        print rule
    else:
        print tabulate(rule, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                      "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")


def dfw_rule_applyto_delete(client_session, rule_id, applyto):
    """
    This function delete one of the applyto clauses of a dfw rule given the rule id and the clause to be deleted.
    If two or more clauses have the same name, the function will delete all of them
    :param client_session: An instance of an NsxClient Session
    :param rule_id: The ID of the dfw rule to retrieve
    :param applyto: The name of the applyto clause of the dfw rule to be deleted. If it contains any space, then
                    it must be enclosed in double quotes (like "VM Network").
    :return: returns
            - tabular view of the dfw rule after the deletion process has been performed
            - ( verbose option ) a list containing a list with the following dfw rule information after the deletion
              process has been performed: ID(Rule)- Name(Rule)- Source- Destination- Services- Action - Direction-
              Pktytpe- AppliedTo- ID(section)
    """

    apply_to = str(applyto)
    rule = dfw_rule_read(client_session, rule_id)

    if len(rule) == 0:
        # It means a rule with id = rule_id does not exist
        result = [[rule_id, "---", "---", "---", "---", "---", "---", "---", apply_to, "---"]]
        return result

    # Get the rule data structure that will be modified and then piped into the update function
    section_list = dfw_section_list(client_session)
    sections = [section_list[0], section_list[1], section_list[2]]
    section_id = rule[0][-1]

    rule_type_selector = ''
    for scan in sections:
        for val in scan:
            if val[1] == section_id:
                rule_type_selector = val[2]

    if rule_type_selector == '':
        print 'ERROR: RULE TYPE SELECTOR CANNOT BE EMPTY - ABORT !'
        return
    if rule_type_selector == 'LAYER2':
        rule_type = 'dfwL2Rule'
    elif rule_type_selector == 'LAYER3':
        rule_type = 'dfwL3Rule'
    else:
        rule_type = 'rule'

    rule_schema = client_session.read(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id})
    rule_etag = rule_schema.items()[-1][1]

    if type(rule_schema.items()[1][1]['rule']['appliedToList']['appliedTo']) == list:
        # It means there are more than one applyto clauses, each one with his own dict
        applyto_list = rule_schema.items()[1][1]['rule']['appliedToList']['appliedTo']
        for i, val in enumerate(applyto_list):
            if 'name' in val and val['name'] == apply_to:
                del rule_schema.items()[1][1]['rule']['appliedToList']['appliedTo'][i]

        # The order dict "rule_schema" must be parsed to find the dict that will be piped into the update function
        rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                     request_body_dict=rule_schema.items()[1][1],
                                     additional_headers={'If-match': rule_etag})
        rule = dfw_rule_read(client_session, rule_id)
        return rule

    if type(rule_schema.items()[1][1]['rule']['appliedToList']['appliedTo']) == dict:
        # It means there is just one explicit applyto clause with his dict
        applyto_dict = rule_schema.items()[1][1]['rule']['appliedToList']['appliedTo']
        val = applyto_dict

        if 'name' in val and val['name'] == "DISTRIBUTED_FIREWALL":
            # It means the only applyto clause is "DISTRIBUTED_FIREWALL" and it cannot be deleted short of deleting
            # the whole rule
            rule = dfw_rule_read(client_session, rule_id)
            return rule

        if 'name' in val and val['name'] == apply_to:
            del rule_schema.items()[1][1]['rule']['appliedToList']
            rule = client_session.update(rule_type, uri_parameters={'ruleId': rule_id, 'sectionId': section_id},
                                         request_body_dict=rule_schema.items()[1][1],
                                         additional_headers={'If-match': rule_etag})

        rule = dfw_rule_read(client_session, rule_id)
        return rule


def _dfw_rule_applyto_delete_print(client_session, **kwargs):
    if not (kwargs['dfw_rule_id']):
        print ('Mandatory parameters missing: [-rid RULE ID]')
        return None
    if not (kwargs['dfw_rule_applyto']):
        print ('Mandatory parameters missing: [-appto RULE APPLYTO]')
        return None
    rule_id = kwargs['dfw_rule_id']
    applyto = kwargs['dfw_rule_applyto']
    rule = dfw_rule_applyto_delete(client_session, rule_id, applyto)
    if kwargs['verbose']:
        print rule
    else:
        print tabulate(rule, headers=["ID", "Name", "Source", "Destination", "Service", "Action", "Direction",
                                      "Packet Type", "Applied-To", "ID (Section)"], tablefmt="psql")


def dfw_section_read(client_session, dfw_section_id):
    """
    This function retrieves details of a dfw section given its id
    :param client_session: An instance of an NsxClient Session
    :param dfw_section_id: The ID of the dfw section to retrieve details from
    :return: returns
            - a tabular view of the section with the following information: Name, Section id, Section type, Etag
            - ( verbose option ) a dictionary containing all sections's details
    """
    section_list = []
    dfw_section_id = str(dfw_section_id)
    uri_parameters = {'sectionId': dfw_section_id}

    dfwL3_section_details = dict(client_session.read('dfwL3SectionId', uri_parameters))

    section_name = dfwL3_section_details['body']['section']['@name']
    section_id = dfwL3_section_details['body']['section']['@id']
    section_type = dfwL3_section_details['body']['section']['@type']
    section_etag = dfwL3_section_details['Etag']
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


def dfw_section_create(client_session, dfw_section_name, dfw_section_type):
    """
    This function creates a new dfw section given its name and its type
    The new section is created on top of all other existing sections and with no rules
    If a section of the same time and with the same name already exist, nothing is done
    :param client_session: An instance of an NsxClient Session
    :param dfw_section_name: The name of the dfw section to be created
    :param dfw_section_type: The type of the section. Allowed values are L2/L3/L3R
    :return: returns
            - a tabular view of all the sections of the same type of the one just created. The table contains the
              following information: Name, Section id, Section type
            - ( verbose option ) a dictionary containing for each possible type all sections' details, including
              dfw rules
    """

    dfw_section_name = str(dfw_section_name)
    dfw_section_selector = str(dfw_section_type)

    if dfw_section_selector != 'L2' and dfw_section_selector != 'L3' and dfw_section_selector != 'L3R':
        print ('Section Type Unknown - Allowed values are L2/L3/L3R -- Aborting')
        return

    if dfw_section_selector == 'L2':
        dfw_section_type = 'dfwL2Section'

    elif dfw_section_selector == 'L3':
        dfw_section_type = 'dfwL3Section'

    else:
        dfw_section_type = 'layer3RedirectSections'

    # Regardless of the final rule type this line below is the correct way to get the empty schema
    section_schema = client_session.extract_resource_body_example('dfwL3Section', 'create')
    section_schema['section']['@name'] = dfw_section_name

    # Delete the rule section to create an empty section
    del section_schema['section']['rule']

    # Check for duplicate sections of the same type as the one that will be created, create and return
    l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)

    if dfw_section_type == 'dfwL2Section':
        for val in l2_section_list:
            if dfw_section_name in val:
                # Section with the same name already exist
                return l2_section_list, detailed_dfw_sections
        section = client_session.create(dfw_section_type, request_body_dict=section_schema)
        l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
        return l2_section_list, detailed_dfw_sections

    if dfw_section_type == 'dfwL3Section':
        for val in l3_section_list:
            if dfw_section_name in val:
                # Section with the same name already exist
                return l3_section_list, detailed_dfw_sections
        section = client_session.create(dfw_section_type, request_body_dict=section_schema)
        l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
        return l3_section_list, detailed_dfw_sections

    if dfw_section_type == 'layer3RedirectSections':
        for val in l3r_section_list:
            if dfw_section_name in val:
                # Section with the same name already exist
                return l3r_section_list, detailed_dfw_sections
        section = client_session.create(dfw_section_type, request_body_dict=section_schema)
        l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
        return l3r_section_list, detailed_dfw_sections


def _dfw_section_create_print(client_session, **kwargs):
    if not (kwargs['dfw_section_name']):
        print ('Mandatory parameters missing: [-sname SECTION NAME]')
        return None

    if not (kwargs['dfw_section_type']):
        print ('Mandatory parameters missing: [-stype SECTION TYPE]')
        return None

    dfw_section_name = kwargs['dfw_section_name']
    dfw_section_type = kwargs['dfw_section_type']

    section_list, detailed_dfw_sections = dfw_section_create(client_session, dfw_section_name, dfw_section_type)

    if kwargs['verbose']:
        print detailed_dfw_sections
    else:
        print tabulate(section_list, headers=["Name", "ID", "Type"], tablefmt="psql")


def contruct_parser(subparsers):
    parser = subparsers.add_parser('dfw', description="Functions for distributed firewall",
                                   help="Functions for distributed firewall",
                                   formatter_class=RawTextHelpFormatter)

    parser.add_argument("command", help="""
    list_sections:   return a list of all distributed firewall's sections
    read_section:    return the details of a dfw section given its id
    read_section_id: return the id of a section given its name (case sensitive)
    create_section:  create a new section given its name and its type (L2,L3,L3R)
    list_rules:      return a list of all distributed firewall's rules
    read_rule:       return the details of a dfw rule given its id
    read_rule_id:    return the id of a rule given its name and the id of the section to which it belongs
    create_rule:     create a new rule given the id of the section, the rule name and all the rule parameters
    delete_section:  delete a section given its id
    delete_rule:     delete a rule given its id
    delete_rule_source: delete one rule's source given the rule id and the source identifier
    delete_rule_destination: delete one rule's destination given the rule id and the destination identifier
    delete_rule_service: delete one rule's service given the rule id and the service identifier
    delete_rule_applyto: delete one rule's applyto clause given the rule id and the applyto clause identifier
    move_rule_above:   move one rule above another rule given the id of the rule to be moved and the id of the base rule
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
    parser.add_argument("-dir",
                        "--dfw_rule_direction",
                        help="dfw rule direction")
    parser.add_argument("-pktype",
                        "--dfw_rule_pktype",
                        help="dfw rule packet type")
    parser.add_argument("-disabled",
                        "--dfw_rule_disabled",
                        help="dfw rule disabled")
    parser.add_argument("-action",
                        "--dfw_rule_action",
                        help="dfw rule action")
    parser.add_argument("-src",
                        "--dfw_rule_source",
                        help="dfw rule source")
    parser.add_argument("-srctype",
                        "--dfw_rule_source_type",
                        help="dfw rule source type")
    parser.add_argument("-srcname",
                        "--dfw_rule_source_name",
                        help="dfw rule source name")
    parser.add_argument("-srcvalue",
                        "--dfw_rule_source_value",
                        help="dfw rule source value")
    parser.add_argument("-srcexcluded",
                        "--dfw_rule_source_excluded",
                        help="dfw rule source excluded")
    parser.add_argument("-dst",
                        "--dfw_rule_destination",
                        help="dfw rule destination")
    parser.add_argument("-dsttype",
                        "--dfw_rule_destination_type",
                        help="dfw rule destination type")
    parser.add_argument("-dstname",
                        "--dfw_rule_destination_name",
                        help="dfw rule destination name")
    parser.add_argument("-dstvalue",
                        "--dfw_rule_destination_value",
                        help="dfw rule destination value")
    parser.add_argument("-dstexcluded",
                        "--dfw_rule_destination_excluded",
                        help="dfw rule destination excluded")
    parser.add_argument("-srv",
                        "--dfw_rule_service",
                        help="dfw rule service")
    parser.add_argument("-srvprotoname",
                        "--dfw_rule_service_protocolname",
                        help="dfw rule service protocol name")
    parser.add_argument("-srvdestport",
                        "--dfw_rule_service_destport",
                        help="dfw rule service destination port")
    parser.add_argument("-srvsrcport",
                        "--dfw_rule_service_srcport",
                        help="dfw rule service source port")
    parser.add_argument("-srvname",
                        "--dfw_rule_service_name",
                        help="dfw rule service name")
    parser.add_argument("-appto",
                        "--dfw_rule_applyto",
                        help="dfw rule applyto")
    parser.add_argument("-note",
                        "--dfw_rule_note",
                        help="dfw rule note")
    parser.add_argument("-tag",
                        "--dfw_rule_tag",
                        help="dfw rule tag")
    parser.add_argument("-logged",
                        "--dfw_rule_logged",
                        help="dfw rule logged")
    parser.add_argument("-brid",
                        "--dfw_rule_base_id",
                        help="dfw rule base id")
    parser.add_argument("-stype",
                        "--dfw_section_type",
                        help="dfw section type")

    parser.set_defaults(func=_dfw_main)


def _dfw_main(args):
    if args.debug:
        debug = True
    else:
        debug = False

    config = ConfigParser.ConfigParser()
    assert config.read(args.ini), 'could not read config file {}'.format(args.ini)

    try:
        nsxramlfile = config.get('nsxraml', 'nsxraml_file')
    except (ConfigParser.NoSectionError):
        nsxramlfile_dir = resource_filename(__name__, 'api_spec')
        nsxramlfile = '{}/nsxvapi.raml'.format(nsxramlfile_dir)

    client_session = NsxClient(nsxramlfile, config.get('nsxv', 'nsx_manager'),
                               config.get('nsxv', 'nsx_username'), config.get('nsxv', 'nsx_password'), debug=debug)

    vccontent = connect_to_vc(config.get('vcenter', 'vcenter'), config.get('vcenter', 'vcenter_user'),
                              config.get('vcenter', 'vcenter_passwd'))

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
            'delete_rule_source': _dfw_rule_source_delete_print,
            'delete_rule_destination': _dfw_rule_destination_delete_print,
            'delete_rule_service': _dfw_rule_service_delete_print,
            'delete_rule_applyto': _dfw_rule_applyto_delete_print,
            'create_section': _dfw_section_create_print,
            'create_rule': _dfw_rule_create_print,
            }
        command_selector[args.command](client_session, vccontent=vccontent, verbose=args.verbose,
                                       dfw_section_id=args.dfw_section_id,
                                       dfw_rule_id=args.dfw_rule_id, dfw_section_name=args.dfw_section_name,
                                       dfw_rule_name=args.dfw_rule_name, dfw_rule_source=args.dfw_rule_source,
                                       dfw_rule_destination=args.dfw_rule_destination,
                                       dfw_rule_service=args.dfw_rule_service, dfw_rule_applyto=args.dfw_rule_applyto,
                                       dfw_rule_base_id=args.dfw_rule_base_id, dfw_section_type=args.dfw_section_type,
                                       dfw_rule_direction=args.dfw_rule_direction, dfw_rule_pktype=args.dfw_rule_pktype,
                                       dfw_rule_disabled=args.dfw_rule_disabled, dfw_rule_action=args.dfw_rule_action,
                                       dfw_rule_source_type=args.dfw_rule_source_type,
                                       dfw_rule_source_name=args.dfw_rule_source_name,
                                       dfw_rule_source_value=args.dfw_rule_source_value,
                                       dfw_rule_source_excluded=args.dfw_rule_source_excluded,
                                       dfw_rule_destination_type=args.dfw_rule_destination_type,
                                       dfw_rule_destination_name=args.dfw_rule_destination_name,
                                       dfw_rule_destination_value=args.dfw_rule_destination_value,
                                       dfw_rule_destination_excluded=args.dfw_rule_destination_excluded,
                                       dfw_rule_service_protocolname=args.dfw_rule_service_protocolname,
                                       dfw_rule_service_destport=args.dfw_rule_service_destport,
                                       dfw_rule_service_srcport=args.dfw_rule_service_srcport,
                                       dfw_rule_service_name=args.dfw_rule_service_name,
                                       dfw_rule_tag=args.dfw_rule_tag, dfw_rule_note=args.dfw_rule_note,
                                       dfw_rule_logged=args.dfw_rule_logged,)

    except KeyError as e:
        print('Unknown command {}'.format(e))


def main():
    main_parser = argparse.ArgumentParser()
    subparsers = main_parser.add_subparsers()
    contruct_parser(subparsers)
    args = main_parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
