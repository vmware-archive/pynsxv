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
from tabulate import tabulate
from nsxramlclient.client import NsxClient
from argparse import RawTextHelpFormatter
from libutils import dfw_rule_list_helper

__author__ = 'Dimitri Desmidt, Emanuele Mazza, Yves Fauser'


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
    :param dfw_section_name: The name ( case sensitive ) of the section for which the ID is wanted
    :return returns
            - A list of dictionaries. Each dictionary contains the type and the id of each section with named as
              specified by the input parameter. If no such section exist, the list contain a single dictionary with
              {'Type': 0, 'Id': 0}
    """
    l2_section_list, l3r_section_list, l3_section_list, detailed_dfw_sections = dfw_section_list(client_session)
    dfw_section_id = list()
    print dfw_section_id
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
    print dfw_section_id


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
    parser.add_argument("-src",
                        "--dfw_rule_source",
                        help="dfw rule source")
    parser.add_argument("-dst",
                        "--dfw_rule_destination",
                        help="dfw rule destination")
    parser.add_argument("-srv",
                        "--dfw_rule_service",
                        help="dfw rule service")
    parser.add_argument("-appto",
                        "--dfw_rule_applyto",
                        help="dfw rule applyto")
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
            'delete_rule_source': _dfw_rule_source_delete_print,
            'delete_rule_destination': _dfw_rule_destination_delete_print,
            'delete_rule_service': _dfw_rule_service_delete_print,
            'delete_rule_applyto': _dfw_rule_applyto_delete_print,
            'create_section': _dfw_section_create_print,
            }
        command_selector[args.command](client_session, verbose=args.verbose, dfw_section_id=args.dfw_section_id,
                                       dfw_rule_id=args.dfw_rule_id, dfw_section_name=args.dfw_section_name,
                                       dfw_rule_name=args.dfw_rule_name, dfw_rule_source=args.dfw_rule_source,
                                       dfw_rule_destination=args.dfw_rule_destination,
                                       dfw_rule_service=args.dfw_rule_service, dfw_rule_applyto=args.dfw_rule_applyto,
                                       dfw_rule_base_id=args.dfw_rule_base_id, dfw_section_type=args.dfw_section_type)

    except KeyError:
        print('Unknown command ')


def main():
    main_parser = argparse.ArgumentParser()
    subparsers = main_parser.add_subparsers()
    contruct_parser(subparsers)
    args = main_parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
