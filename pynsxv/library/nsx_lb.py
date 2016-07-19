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
import json
from tabulate import tabulate
from libutils import get_edge, check_for_parameters
from nsxramlclient.client import NsxClient
from argparse import RawTextHelpFormatter
from pkg_resources import resource_filename


__author__ = 'yfauser'


def add_app_profile(client_session, esg_name, prof_name, template, persistence=None, expire_time=None, cookie_name=None,
                    cookie_mode=None, xforwardedfor=None, http_redir_url=None):
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    app_prof = client_session.extract_resource_body_example('applicationProfiles', 'create')

    app_prof['applicationProfile']['name'] = prof_name
    app_prof['applicationProfile']['template'] = template

    persist = None
    if persistence == 'sourceip':
        if expire_time:
            persist = {'method': 'sourceip', 'expire': expire_time}
        else:
            persist = {'method': 'sourceip'}
    elif persistence == 'msrdp':
        if expire_time:
            persist = {'method': 'msrdp', 'expire': expire_time}
        else:
            persist = {'method': 'msrdp'}
    elif persistence == 'cookie':
        if expire_time:
            persist = {'method': 'cookie', 'expire': expire_time, 'cookieName': cookie_name, 'cookieMode': cookie_mode}
        else:
            persist = {'method': 'cookie', 'cookieName': cookie_name, 'cookieMode': cookie_mode}

    if persist:
        app_prof['applicationProfile']['persistence'] = persist
    else:
        app_prof['applicationProfile']['persistence'] = None

    if xforwardedfor == 'true':
        app_prof['applicationProfile']['insertXForwardedFor'] = 'true'
    else:
        app_prof['applicationProfile']['insertXForwardedFor'] = 'false'

    if http_redir_url:
        app_prof['applicationProfile']['httpRedirect'] = {'to': http_redir_url}

    result = client_session.create('applicationProfiles', uri_parameters={'edgeId': esg_id},
                                     request_body_dict=app_prof)
    if result['status'] != 201:
        return None
    else:
        return result['objectId']


def _add_app_profile(client_session, **kwargs):
    needed_params = ['esg_name', 'profile_name', 'profile_type']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = add_app_profile(client_session, kwargs['esg_name'], kwargs['profile_name'], kwargs['profile_type'],
                             persistence=kwargs['persistence'], expire_time=kwargs['expire'],
                             cookie_name=kwargs['cookie_name'], cookie_mode=kwargs['cookie_mode'],
                             xforwardedfor=kwargs['xforwardedfor'], http_redir_url=kwargs['http_redir_url'])

    if result and kwargs['verbose']:
        print result
    elif result:
        print 'LB App Profile configuration on esg {} succeeded, the App Profile Id is {}'.format(kwargs['esg_name'],
                                                                                                  result)
    else:
        print 'LB App configuration on esg {} failed'.format(kwargs['esg_name'])


def read_app_profile(client_session, esg_name, prof_name):
    #TODO: Finds an App profile by name and returns its ID
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    prof_list, prof_list_verbose = list_app_profiles(client_session, esg_name)

    try:
        profile_id = [prof[0] for prof in prof_list if prof[1] == prof_name][0]
    except IndexError:
        return None

    result = client_session.read('applicationProfile', uri_parameters={'edgeId': esg_id,
                                                                       'appProfileID': profile_id})
    profile_id = result['body']['applicationProfile']['applicationProfileId']
    profile_details = result['body']['applicationProfile']

    return profile_id, profile_details

def _read_app_profile(client_session, **kwargs):
    needed_params = ['esg_name', 'profile_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    profile_id, profile_details = read_app_profile(client_session, kwargs['esg_name'], kwargs['profile_name'])

    if kwargs['verbose']:
        print profile_id
    else:
        print 'LB App Profile {} on ESG {} has the Id: {}'.format(kwargs['profile_name'],
                                                                  kwargs['esg_name'], profile_id)

def delete_app_profile(client_session, esg_name, prof_id):
    #TODO: Finds an App profile by name and deletes it
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    result = client_session.delete('applicationProfile', uri_parameters={'edgeId': esg_id,
                                                                         'appProfileID': prof_id})

    if result['status'] == 204:
        return True
    else:
        return None


def _delete_app_profile(client_session, **kwargs):
    needed_params = ['esg_name', 'profile_id']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = delete_app_profile(client_session, kwargs['esg_name'], kwargs['profile_id'])

    if result:
        print 'Deleting Application Profile {} on esg {} succeeded'.format(kwargs['profile_id'], kwargs['esg_name'])
    else:
        print 'Deleting Application Profile {} on esg {} failed'.format(kwargs['profile_id'], kwargs['esg_name'])


def list_app_profiles(client_session, esg_name):
    #TODO: Lists all app profiles and returns a list
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    app_profiles_api = client_session.read('applicationProfiles', uri_parameters={'edgeId': esg_id})['body']
    if app_profiles_api['loadBalancer']:
        if 'applicationProfile' in app_profiles_api['loadBalancer']:
            profs = client_session.normalize_list_return(app_profiles_api['loadBalancer']['applicationProfile'])
        else:
            profs = []
    else:
        profs = []

    prof_lst = []
    for prof in profs:
        prof_id = prof.get('applicationProfileId')
        prof_name = prof.get('name')
        template = prof.get('template')

        if 'persistence' in prof:
            val = prof.get('persistence')
            persistence = val.get('method')
            expire_time = val.get('expire')
            cookie_name = val.get('cookieName')
            cookie_mode = val.get('cookieMode')
        else:
            persistence, expire_time, cookie_name, cookie_mode = None, None, None, None

        xforwardedfor = prof.get('insertXForwardedFor')

        if 'httpRedirect' in prof:
            val = prof.get('httpRedirect')
            http_redir_url = val.get('to')
        else:
            http_redir_url = None

        prof_lst.append((prof_id, prof_name, template, persistence, expire_time, cookie_name,
                         cookie_mode, xforwardedfor, http_redir_url))

    prof_lst_verbose = profs

    return prof_lst, prof_lst_verbose


def _list_app_profiles(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    prof_list, prof_list_verbose = list_app_profiles(client_session, kwargs['esg_name'])

    if kwargs['verbose']:
        print json.dumps(prof_list_verbose)
    else:
        print tabulate(prof_list, headers=["App Prof. Id", "App Prof. Name", "App Prof. Type", "Persist. Type",
                                           "Expiry", "Cookie Name", "Cookie Mode", "XForward. For Insert",
                                           "HTTP redir. URL"], tablefmt="psql")


def contruct_parser(subparsers):
    parser = subparsers.add_parser('lb', description="Functions for Load Balancer configurations "
                                                     "on Edge Service Gateways",
                                   help="Functions for Edge Load Balancer",
                                   formatter_class=RawTextHelpFormatter)

    parser.add_argument("command", help="""
    add_profile:        Add an application profile on the Load Balancer
    delete_profile:     Deletes an application profile of the Load Balancer
    read_profile:       Returns the application profile Id from the Load Balancer
    list_profiles:      Lists all application profiles configured on the Load Balancer
    """)

    parser.add_argument("-n",
                        "--esg_name",
                        help="ESG name")
    parser.add_argument("-pn",
                        "--profile_name",
                        help="Application Profile Name")
    parser.add_argument("-pi",
                        "--profile_id",
                        help="Application Profile Id")
    parser.add_argument("-pt",
                        "--profile_type",
                        help="Application Profile Type (TCP,UDP,HTTP)")
    parser.add_argument("-p",
                        "--persistence",
                        help="Application Profile Persistence Type (sourceip, msrdp, cookie)")
    parser.add_argument("-ex",
                        "--expire",
                        help="Application Profile session expire time")
    parser.add_argument("-cn",
                        "--cookie_name",
                        help="Application Profile Cookie name used with persistence type cookie")
    parser.add_argument("-cm",
                        "--cookie_mode",
                        help="Application Profile Cookie mode used with persistence type cookie (insert, prefix, app)")
    parser.add_argument("-x",
                        "--xforwardedfor",
                        help="Application Profile enable x forwarded for header (true/false)")
    parser.add_argument("-rd",
                        "--http_redir_url",
                        help="Application Profile HTTP redirect URL for HTTP Types")

    parser.set_defaults(func=_lb_main)


def _lb_main(args):
    if args.debug:
        debug = True
    else:
        debug = False

    config = ConfigParser.ConfigParser()
    assert config.read(args.ini), 'could not read config file {}'.format(args.ini)

    try:
        nsxramlfile = config.get('nsxraml', 'nsxraml_file')
    except ConfigParser.NoSectionError:
        nsxramlfile_dir = resource_filename(__name__, 'api_spec')
        nsxramlfile = '{}/nsxvapi.raml'.format(nsxramlfile_dir)

    client_session = NsxClient(nsxramlfile, config.get('nsxv', 'nsx_manager'),
                               config.get('nsxv', 'nsx_username'), config.get('nsxv', 'nsx_password'), debug=debug)

    try:
        command_selector = {
            'add_profile': _add_app_profile,
            'delete_profile': _delete_app_profile,
            'read_profile': _read_app_profile,
            'list_profiles': _list_app_profiles,
            }
        command_selector[args.command](client_session, esg_name=args.esg_name, profile_name=args.profile_name,
                                       profile_id=args.profile_id, profile_type=args.profile_type,
                                       persistence=args.persistence, expire=args.expire, cookie_name=args.cookie_name,
                                       cookie_mode=args.cookie_mode, xforwardedfor=args.xforwardedfor,
                                       http_redir_url=args.http_redir_url, verbose=args.verbose)
    except KeyError as e:
        print('Unknown command: {}'.format(e))


def main():
    main_parser = argparse.ArgumentParser()
    subparsers = main_parser.add_subparsers()
    contruct_parser(subparsers)
    args = main_parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
