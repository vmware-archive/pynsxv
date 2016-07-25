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
                    cookie_mode=None, xforwardedfor=None, url=None):
    """
    This function adds an Load Balancer Application profile to an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type prof_name: str
    :param prof_name: The name for the to be created Load Balancer Application profile
    :type template: str
    :param template: The protocol template used for this App Profile, can be (TCP, UDP, HTTP, HTTPS)
    :type persistence: str
    :param persistence: The persistence type, can be (none, sourceip, msrdp, cookie)
    :type expire_time: str
    :param expire_time: The expiration type for persistence methods that have a timeout like UDP or TCP
    :type cookie_name: str
    :param cookie_name: The name for the cookie when using the cookie persistence type
    :type cookie_mode: str
    :param cookie_mode: The mode used for the cookie persistence, can be (insert, prefix, app)
    :type xforwardedfor: str
    :param xforwardedfor: Is the X Forwarded For Header inserted or not ('true'/'false')
    :type url: str
    :param url: A URL for HTTP redirection, e.g. http://www.vmware.com
    :return: Returns the Object Id of the newly created Application Profile, False on a failure, and None if the ESG was
             not found in NSX
    :rtype: str
    """
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

    if url:
        app_prof['applicationProfile']['httpRedirect'] = {'to': url}

    result = client_session.create('applicationProfiles', uri_parameters={'edgeId': esg_id},
                                   request_body_dict=app_prof)
    if result['status'] != 201:
        return None
    else:
        return result['objectId']


def _add_app_profile(client_session, **kwargs):
    needed_params = ['esg_name', 'profile_name', 'protocol']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = add_app_profile(client_session, kwargs['esg_name'], kwargs['profile_name'], kwargs['protocol'],
                             persistence=kwargs['persistence'], expire_time=kwargs['expire'],
                             cookie_name=kwargs['cookie_name'], cookie_mode=kwargs['cookie_mode'],
                             xforwardedfor=kwargs['xforwardedfor'], url=kwargs['url'])

    if result and kwargs['verbose']:
        print result
    elif result:
        print 'LB App Profile configuration on esg {} succeeded, the App Profile Id is {}'.format(kwargs['esg_name'],
                                                                                                  result)
    else:
        print 'LB App configuration on esg {} failed'.format(kwargs['esg_name'])


def read_app_profile(client_session, esg_name, prof_name):
    """
    This function read a Load Balancer Application profile on an ESG and returns its Id and details

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type prof_name: str
    :param prof_name: The name for the to be created Load Balancer Application profile
    :return: Returns a tuple, the first item of the tuple contains the Id of the profile as a string, the second
             item contains the profile details returned from the NSX API as a dict
    :rtype: tuple
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None, None

    prof_list, prof_list_verbose = list_app_profiles(client_session, esg_name)

    try:
        profile_id = [prof[0] for prof in prof_list if prof[1] == prof_name][0]
    except IndexError:
        return None, None

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
    """
    This function deletes an Load Balancing Application Profile on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type prof_id: str
    :param prof_id: The Id of the Load Balancing Application Profile to be deleted
    :return: True if the deletion was successful, None on failure
    :rtype: bool
    """
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
    """
    This function lists all Load Balancing Application Profiles on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :return: Returns a tuple, the first item containing a list of tuples containing:
             [0] The Id of the Profile
             [1] The name of the Profile
             [2] The Template used (UDP/TCP/HTTP/HTTPS)
             [3] The expiration time for the persistence if used
             [4] The Cookie Name if cookies are used
             [5] The Cookie Mode if cookies are used
             [6] The state of XForwardedFor injection ('true' or 'false')
             [7] The HTTP Redirection URL if set for HTTP types
            The second item contains all profile details on the system as a list of dicts
    :rtype: tuple
    """
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
            url = val.get('to')
        else:
            url = None

        prof_lst.append((prof_id, prof_name, template, persistence, expire_time, cookie_name,
                         cookie_mode, xforwardedfor, url))

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


def add_pool(client_session, esg_name, pool_name, pool_desc=None, algorithm=None, algorithm_params=None, monitor=None,
             transparent=None):
    """
    This function creates a Load Balancing Server Pool on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type pool_name: str
    :param pool_name: The name of the to be created pool
    :type pool_desc: str
    :param pool_desc: A free text description for the pool to be created
    :type algorithm: str
    :param algorithm: The load balancing algorithm for an Server Pool
                      (round-robin, ip-hash, leastconn, uri, httpheader, url)
    :type algorithm_params: str
    :param algorithm_params: Additional parameters for the server pool algorithm
    :type monitor: str
    :param monitor: The name of the monitor used for the server pool
    :type transparent: str
    :param transparent: change the mode of the server pool to transparent ('true'/'false')
    :return: Returns the Object Id of the newly created LB Server Pool, False on a failure, and None if the ESG was
             not found in NSX
    :rtype: str
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    if not algorithm:
        algorithm = 'round-robin'
    if not transparent:
        transparent = 'false'

    if monitor:
        monitor_id, monitor_verbose = read_monitor(client_session, esg_name, monitor)
    else:
        monitor_id = None

    pool = {'pool': {'name': pool_name, 'description': pool_desc, 'transparent': transparent,
                     'algorithm': algorithm, 'monitorId': monitor_id}}

    if algorithm_params:
        pool['pool']['algorithmParameters'] = algorithm

    result = client_session.create('pools', uri_parameters={'edgeId': esg_id}, request_body_dict=pool)

    if result['status'] != 201:
        return None
    else:
        return result['objectId']


def _add_pool(client_session, **kwargs):
    needed_params = ['esg_name', 'pool_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = add_pool(client_session, kwargs['esg_name'], kwargs['pool_name'], kwargs['pool_description'],
                      kwargs['algorithm'], kwargs['algorithm_params'], kwargs['monitor'], kwargs['transparent'])

    if result and kwargs['verbose']:
        print result
    elif result:
        print 'LB Server Pool configuration on esg {} succeeded, the Pool Id is {}'.format(kwargs['esg_name'], result)
    else:
        print 'LB Server Pool configuration on esg {} failed'.format(kwargs['esg_name'])


def read_pool(client_session, esg_name, pool_name):
    """
    This function returns the Id and Details of a Load Balancing Server Pool on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type pool_name: str
    :param pool_name: The name of the to be created pool
    :return: Returns a tuple, the first item of the tuple contains the Id of the pool as a string, the second
             item contains the pool details returned from the NSX API as a dict
    :rtype: tuple
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None, None

    pool_list, pool_list_verbose = list_pools(client_session, esg_name)

    try:
        pool_id = [pool[0] for pool in pool_list if pool[1] == pool_name][0]
    except IndexError:
        return None, None

    result = client_session.read('pool', uri_parameters={'edgeId': esg_id, 'poolID': pool_id})

    pool_id = result['body']['pool']['poolId']
    pool_details = result['body']['pool']

    return pool_id, pool_details


def _read_pool(client_session, **kwargs):
    needed_params = ['esg_name', 'pool_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    pool_id, pool_details = read_pool(client_session, kwargs['esg_name'], kwargs['pool_name'])

    if kwargs['verbose']:
        print pool_id
    else:
        print 'LB Server Pool {} on ESG {} has the Id: {}'.format(kwargs['profile_name'],
                                                                  kwargs['esg_name'], pool_id)


def delete_pool(client_session, esg_name, pool_id):
    """
    This function deletes a Load Balancing Server Pool on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type pool_id: str
    :param pool_id: The pool Id of the pool that is to be deleted
    :return: Returns True on successful deletion of the pool and None on failure or if the ESG was not found
    :rtype: bool
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    result = client_session.delete('pool', uri_parameters={'edgeId': esg_id, 'poolID': pool_id})

    if result['status'] == 204:
        return True
    else:
        return None


def _delete_pool(client_session, **kwargs):
    needed_params = ['esg_name', 'pool_id']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = delete_pool(client_session, kwargs['esg_name'], kwargs['pool_id'])

    if result:
        print 'Deleting LB Server Pool {} on esg {} succeeded'.format(kwargs['pool_id'], kwargs['esg_name'])
    else:
        print 'Deleting LB Server Pool {} on esg {} failed'.format(kwargs['pool_id'], kwargs['esg_name'])


def list_pools(client_session, esg_name):
    """
    This function lists all LB Server Pools on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :return: Returns a tuple, the first item containing a list of tuples containing:
             [0] The Id of the pool
             [1] The name of the pool
             [2] The description attached to the pool
             [3] The load balancing algorithm used for the pool
             [4] Additional algorithm parameters used for the pool
             [5] The Id of the monitor used with this pool
             [6] Transparent operation ('true'/'false')
            The second item contains all pool details on the system as a list of dicts
    :rtype: tuple
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    pools_api = client_session.read('pools', uri_parameters={'edgeId': esg_id})['body']
    if pools_api['loadBalancer']:
        if 'pool' in pools_api['loadBalancer']:
            pools = client_session.normalize_list_return(pools_api['loadBalancer']['pool'])
        else:
            pools = []
    else:
        pools = []

    pool_lst = [(pool.get('poolId'), pool.get('name'), pool.get('description'), pool.get('algorithm'),
                 pool.get('algorithmParameters'), pool.get('monitorId'), pool.get('transparent')) for pool in pools]

    pool_lst_verbose = [pool for pool in pools]

    return pool_lst, pool_lst_verbose


def _list_pools(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    pool_list, pool_list_verbose = list_pools(client_session, kwargs['esg_name'])

    if kwargs['verbose']:
        print json.dumps(pool_list_verbose)
    else:
        print tabulate(pool_list, headers=["Pool Id", "Pool Name", "Description", "Algorithm", "Alg. Parameter",
                                           "Monitor Id", "Is transparent"], tablefmt="psql")


def add_member(client_session, esg_name, pool_name, member_name, member_ip, port=None, monitor_port=None, weight=None,
               max_conn=None, min_conn=None):
    """
    This function creates a Member inside a Server Pool on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type pool_name: str
    :param pool_name: The name of the pool where the member should be added to
    :type member_name: str
    :param member_name: The name of the to be added member
    :type member_ip: str
    :param member_ip: The IP address of the member to be added
    :type port: str
    :param port: The port number the member is listening to
    :type monitor_port: str
    :param monitor_port: The port number to monitor on the member
    :type weight: str
    :param weight: The weight of the member in the server pool
    :type max_conn: str
    :param max_conn: The maximum connections this member can hold
    :type min_conn: str
    :param min_conn: The minimum connections this member should hold
    :return: Returns the Object Id of the newly created member in the Server Pool, False on a failure,
             and None if the ESG was not found in NSX
    :rtype: str
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    pool_id, pool_details = read_pool(client_session, esg_name, pool_name)

    if pool_details:
        if 'member' in pool_details:
            members = client_session.normalize_list_return(pool_details['member'])
        else:
            pool_details['member'] = []
            members = []
    else:
        pool_details['member'] = []
        members = []

    new_member = {'name': member_name, 'ipAddress': member_ip, 'port': port, 'monitorPort': monitor_port,
                  'weight': weight, 'maxConn': max_conn, 'minConn': min_conn}

    members.append(new_member)
    pool_details['member'] = members

    result = client_session.update('pool', uri_parameters={'edgeId': esg_id, 'poolID': pool_id},
                                   request_body_dict={'pool': pool_details})
    if result['status'] != 204:
        return False
    else:
        return True


def _add_member(client_session, **kwargs):
    needed_params = ['esg_name', 'member_name', 'member', 'pool_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = add_member(client_session, kwargs['esg_name'], kwargs['pool_name'], kwargs['member_name'],
                        kwargs['member'], kwargs['port'], kwargs['monitor_port'], kwargs['weight'], kwargs['max_conn'],
                        kwargs['min_conn'])

    if result and kwargs['verbose']:
        print result
    elif result:
        print 'LB Member configuration on esg {} succeeded'.format(kwargs['esg_name'])
    else:
        print 'LB Member configuration  on esg {} failed'.format(kwargs['esg_name'])


def read_member(client_session, esg_name, pool_name, member_name):
    """
    This reads the details of a Member inside a Server Pool on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type pool_name: str
    :param pool_name: The name of the pool where this member is present in
    :type member_name: str
    :param member_name: The name of searched member in the server pool
    :return: Returns a tuple, the first item of the tuple contains the Id of the member as a string, the second
             item contains the member details returned from the NSX API as a dict
    :rtype: tuple
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None, None

    pool_id, pool_details = read_pool(client_session, esg_name, pool_name)
    if not pool_id:
        return None, None

    if pool_details:
        if 'member' in pool_details:
            members = client_session.normalize_list_return(pool_details['member'])
        else:
            members = []
    else:
        members = []
    try:
        member = [member for member in members if member['name'] == member_name][0]
    except IndexError:
        return None, None

    return member['memberId'], member


def _read_member(client_session, **kwargs):
    needed_params = ['esg_name', 'pool_name', 'member_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    member_id, member_details = read_member(client_session, kwargs['esg_name'], kwargs['pool_name'],
                                            kwargs['member_name'])

    if kwargs['verbose']:
        print member_id
    else:
        print 'Member {} in Pool {} on esg {} has the Id: {}'.format(kwargs['member_name'], kwargs['pool_name'],
                                                                     kwargs['esg_name'], member_id)


def delete_member(client_session, esg_name, pool_name, member_id):
    """
    This function deletes a Member from a Server Pool on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type pool_name: str
    :param pool_name: The name of the pool where this member is present in
    :type member_id: str
    :param member_id: The Id of the member to be deleted from the server pool
    :return: Returns True on successful deletion of the member and None on failure or if the ESG was not found
    :rtype: bool
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    pool_id, pool_details = read_pool(client_session, esg_name, pool_name)
    if not pool_id:
        return None

    if pool_details:
        if 'member' in pool_details:
            members = client_session.normalize_list_return(pool_details['member'])
        else:
            pool_details['member'] = []
            members = []
    else:
        pool_details['member'] = []
        members = []

    members_new = [member for member in members if member['memberId'] != member_id]

    pool_details['member'] = members_new

    result = client_session.update('pool', uri_parameters={'edgeId': esg_id, 'poolID': pool_id},
                                   request_body_dict={'pool': pool_details})
    if result['status'] != 204:
        return False
    else:
        return True


def _delete_member(client_session, **kwargs):
    needed_params = ['esg_name', 'pool_name', 'member_id']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = delete_member(client_session, kwargs['esg_name'], kwargs['pool_name'], kwargs['member_id'])

    if result:
        print 'Deleting Member {} in Pool {} on esg {} succeeded'.format(kwargs['member_id'], kwargs['pool_name'],
                                                                         kwargs['esg_name'])
    else:
        print 'Deleting Member {} in Pool {} on esg {} failed'.format(kwargs['pool_id'], kwargs['pool_name'],
                                                                      kwargs['esg_name'])


def list_members(client_session, esg_name, pool_name):
    """
    This function lists all Members in a Server Pool on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type pool_name: str
    :param pool_name: The name of the LB Server Pool
    :return: Returns a tuple, the first item containing a list of tuples containing:
             [0] The Id of the Member
             [1] The name of the Member
             [2] The IP Address of the member
             [3] The port the member listens on
             [4] The monitor of the member
             [5] The weight of the member
             [6] The maximum connections allowed for this member
             [7] The minimum connection for this member
             [8] The state of the member ('enabled'/'disabled')
            The second item contains all member details on the system as a list of dicts
    :rtype: tuple
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    pool_id, pool_details = read_pool(client_session, esg_name, pool_name)

    if pool_details:
        if 'member' in pool_details:
            members = client_session.normalize_list_return(pool_details['member'])
        else:
            members = []
    else:
        members = []

    member_lst = [(member.get('memberId'), member.get('name'), member.get('ipAddress'), member.get('port'),
                   member.get('monitorPort'), member.get('weight'), member.get('maxConn'), member.get('minConn'),
                   member.get('condition')) for member in members]

    member_lst_verbose = [member for member in members]

    return member_lst, member_lst_verbose


def _list_members(client_session, **kwargs):
    needed_params = ['esg_name', 'pool_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    member_list, member_list_verbose = list_members(client_session, kwargs['esg_name'], kwargs['pool_name'])

    if kwargs['verbose']:
        print json.dumps(member_list_verbose)
    else:
        print tabulate(member_list, headers=["Member Id", "Member Name", "Member", "Port", "Monitor Port", "Weight",
                                             "Max Conn", "Min Conn", "Condition"], tablefmt="psql")


def add_vip(client_session, esg_name, vip_name, app_profile, vip_ip, protocol, port, pool_name, vip_description=None,
            conn_limit=None, conn_rate_limit=None, acceleration=None):
    """
    This function creates a Load Balancing Virtual IP / Virtual Server (VIP) on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type vip_name: str
    :param vip_name: The name of a virtual server (VIP)
    :type app_profile: str
    :param app_profile: The name of the LB App Profile to be used for this VIP
    :type vip_ip: str
    :param vip_ip: The IP Address of a virtual server (VIP), this address needs to be the IP of a vnic on the ESG
    :type protocol: str
    :param protocol: The protocol used for this VIP (UDP, TCP, HTTP, HTTPS)
    :type port: str
    :param port: The port this VIP listens to
    :type pool_name: str
    :param pool_name: The name of the pool to be attached to this VIP
    :type vip_description: str
    :param vip_description: A free text description for the virtual server (VIP)
    :type conn_limit: str
    :param conn_limit: Connection Limit on the virtual server (VIP)
    :type conn_rate_limit: str
    :param conn_rate_limit: Connection rate Limit on the virtual server (VIP)
    :type acceleration: str
    :param acceleration: Is Acceleration enabled for this VIP ('true'/'false')
    :rtype: str
    :return: Returns the Object Id of the newly created VIP, False on a failure, and None if the ESG was
             not found in NSX
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    pool_id, pool_details = read_pool(client_session, esg_name, pool_name)
    if not pool_id:
        return None

    prof_id, prof_details = read_app_profile(client_session, esg_name, app_profile)
    if not prof_id:
        return None

    if acceleration != 'true':
        acceleration = 'false'

    print acceleration

    vip = client_session.extract_resource_body_example('virtualServers', 'create')

    vip['virtualServer']['name'] = vip_name
    vip['virtualServer']['description'] = vip_description
    vip['virtualServer']['enabled'] = 'true'
    vip['virtualServer']['ipAddress'] = vip_ip
    vip['virtualServer']['protocol'] = protocol
    vip['virtualServer']['port'] = port
    vip['virtualServer']['connectionLimit'] = conn_limit
    vip['virtualServer']['connectionRateLimit'] = conn_rate_limit
    vip['virtualServer']['applicationProfileId'] = prof_id
    vip['virtualServer']['defaultPoolId'] = pool_id
    vip['virtualServer']['enableServiceInsertion'] = 'false'
    vip['virtualServer']['accelerationEnabled'] = acceleration

    result = client_session.create('virtualServers', uri_parameters={'edgeId': esg_id}, request_body_dict=vip)

    if result['status'] != 201:
        return None
    else:
        return result['objectId']


def _add_vip(client_session, **kwargs):
    needed_params = ['esg_name', 'pool_name', 'vip_name', 'profile_name', 'vip_ip', 'port', 'protocol']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = add_vip(client_session, kwargs['esg_name'], kwargs['vip_name'], kwargs['profile_name'], kwargs['vip_ip'],
                     kwargs['protocol'], kwargs['port'], kwargs['pool_name'], vip_description=kwargs['vip_description'],
                     conn_limit=kwargs['conn_limit'], conn_rate_limit=kwargs['conn_rate_limit'],
                     acceleration=kwargs['acceleration'])

    if result and kwargs['verbose']:
        print result
    elif result:
        print 'LB VIP configuration on esg {} succeeded, the VIP Id is {}'.format(kwargs['esg_name'], result)
    else:
        print 'LB VIP configuration on esg {} failed'.format(kwargs['esg_name'])


def read_vip(client_session, esg_name, vip_name):
    """
    This function returns the Id and Details of a VIP on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type vip_name: str
    :param vip_name: The name of the VIP searched
    :return: Returns a tuple, the first item of the tuple contains the Id of the VIP as a string, the second
             item contains the VIP details returned from the NSX API as a dict
    :rtype: tuple
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None, None

    vip_list, vip_list_verbose = list_vips(client_session, esg_name)

    try:
        vip_id = [vip[0] for vip in vip_list if vip[1] == vip_name][0]
    except IndexError:
        return None, None

    result = client_session.read('virtualServer', uri_parameters={'edgeId': esg_id, 'virtualserverID': vip_id})

    vip_id = result['body']['virtualServer']['virtualServerId']
    vip_details = result['body']['virtualServer']

    return vip_id, vip_details


def _read_vip(client_session, **kwargs):
    needed_params = ['esg_name', 'vip_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    vip_id, vip_details = read_vip(client_session, kwargs['esg_name'], kwargs['vip_name'])

    if kwargs['verbose']:
        print vip_id
    else:
        print 'LB Server Pool {} on ESG {} has the Id: {}'.format(kwargs['profile_name'],
                                                                  kwargs['esg_name'], vip_id)


def delete_vip(client_session, esg_name, vip_id):
    """
    This function deletes a VIP on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type vip_id: str
    :param vip_id: The Id of the VIP to be deleted
    :return: Returns True on successful deletion of the VIP and None on failure or if the ESG was not found
    :rtype: bool
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    result = client_session.delete('virtualServer', uri_parameters={'edgeId': esg_id, 'virtualserverID': vip_id})

    if result['status'] == 204:
        return True
    else:
        return None


def _delete_vip(client_session, **kwargs):
    needed_params = ['esg_name', 'vip_id']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = delete_vip(client_session, kwargs['esg_name'], kwargs['vip_id'])

    if result:
        print 'Deleting VIP {} on esg {} succeeded'.format(kwargs['vip_id'], kwargs['esg_name'])
    else:
        print 'Deleting VIP {} on esg {} failed'.format(kwargs['vip_id'], kwargs['esg_name'])


def list_vips(client_session, esg_name):
    """
    This function lists all VIPs on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :return: Returns a tuple, the first item containing a list of tuples containing:
             [0] The Id of the VIP
             [1] The name of the VIP
             [2] The description attached to the VIP
             [3] The enabled state of the VIP
             [4] The IP Address the VIP is listening on (needs to be a vnic IP on the ESG)
             [5] The protocol used by the VIP (UDP, TCP, HTTP, HTTPS)
             [6] The port the VIP listens on
             [7] The Id of the server pool attached to the VIP
             [8] The LB App Profile Id attached to the VIP
             [9] The connection limits of the VIP
             [10] The Connection rate limit of the VIP
             [11] The state of the acceleration for the VIP
            The second item contains all VIP details on the system as a list of dicts
    :rtype: tuple
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    vips_api = client_session.read('virtualServers', uri_parameters={'edgeId': esg_id})['body']

    if vips_api['loadBalancer']:
        if 'virtualServer' in vips_api['loadBalancer']:
            vips = client_session.normalize_list_return(vips_api['loadBalancer']['virtualServer'])
        else:
            vips = []
    else:
        vips = []

    vips_lst = [(vip.get('virtualServerId'), vip.get('name'), vip.get('description'), vip.get('enabled'),
                 vip.get('ipAddress'), vip.get('protocol'), vip.get('port'), vip.get('defaultPoolId'),
                 vip.get('applicationProfileId'), vip.get('connectionLimit'), vip.get('connectionRateLimit'),
                 vip.get('accelerationEnabled')) for vip in vips]

    vips_lst_verbose = [vip for vip in vips]

    return vips_lst, vips_lst_verbose


def _list_vips(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    vip_list, vip_list_verbose = list_vips(client_session, kwargs['esg_name'])

    if kwargs['verbose']:
        print json.dumps(vip_list_verbose)
    else:
        print tabulate(vip_list, headers=["VIP Id", "Name", "Desc.", "Enabled", "VIP", "Proto", "Port", "Bound Pool",
                                          "App Prof.", "Conn Limit", "Conn Rate Limit", "Accel. Enabled"],
                       tablefmt="psql")


def add_monitor(client_session, esg_name, monitor_name, protocol, timeout=None, interval=None, max_retries=None,
                mon_expected=None, method=None, url=None, send=None, receive=None, extension=None):
    """
    This function creates a Load Balancing Monitor on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type monitor_name: str
    :param monitor_name: The name of the LB Monitor
    :type protocol: str
    :param protocol: The protocol used for this VIP (UDP, TCP, HTTP, HTTPS, ICMP)
    :type timeout: str
    :param timeout: The Timeout value for a LB Monitor
    :type interval: str
    :param interval: The Interval value for a LB Monitor
    :type max_retries: str
    :param max_retries: The maximum retries for a LB Monitor
    :type mon_expected: str
    :param mon_expected: The expected response for a LB Monitor
    :type method: str
    :param method: The method used for a LB Monitor (GET, POST, OPTIONS)
    :type url: str
    :param url: The URL to use for HTTP and HTTPS protocols
    :type send: str
    :param send: The send value for a LB Monitor
    :type receive: str
    :param receive: The receive value for a LB Monitor
    :type extension: str
    :param extension: Extensions for a LB Monitor
    :rtype: str
    :return: Returns the Object Id of the newly created LB Monitor, False on a failure, and None if the ESG was
             not found in NSX
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None
    if not timeout:
        timeout = '15'
    if not interval:
        interval = '10'
    if not max_retries:
        max_retries = '3'
    if protocol:
        protocol = protocol.lower()
        if (protocol == 'http' or protocol == 'https') and not method:
            method = 'GET'
        if (protocol == 'http' or protocol == 'https') and not url:
            url = '/'

    monitor_spec = client_session.extract_resource_body_example('lbMonitors', 'create')

    monitor_spec['monitor']['name'] = monitor_name
    monitor_spec['monitor']['type'] = protocol
    monitor_spec['monitor']['interval'] = interval
    monitor_spec['monitor']['timeout'] = timeout
    monitor_spec['monitor']['maxRetries'] = max_retries

    if url:
        monitor_spec['monitor']['url'] = url
    if method:
        monitor_spec['monitor']['method'] = method
    if mon_expected:
        monitor_spec['monitor']['expected'] = mon_expected
    if send:
        monitor_spec['monitor']['send'] = send
    if receive:
        monitor_spec['monitor']['receive'] = receive
    if extension:
        monitor_spec['monitor']['extension'] = extension

    result = client_session.create('lbMonitors', uri_parameters={'edgeId': esg_id}, request_body_dict=monitor_spec)

    if result['status'] != 201:
        return None
    else:
        return result['objectId']


def _add_monitor(client_session, **kwargs):
    needed_params = ['esg_name', 'mon_name', 'protocol']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = add_monitor(client_session, kwargs['esg_name'], kwargs['mon_name'], kwargs['protocol'],
                         timeout=kwargs['timeout'], max_retries=kwargs['max_retries'], url=kwargs['url'],
                         mon_expected=kwargs['mon_expected'], method=kwargs['method'], send=kwargs['send'],
                         receive=kwargs['receive'], extension=kwargs['extension'], interval=kwargs['interval'])

    if result and kwargs['verbose']:
        print result
    elif result:
        print 'LB Monitor configuration on esg {} succeeded, the Monitor Id is {}'.format(kwargs['esg_name'], result)
    else:
        print 'LB Monitor configuration on esg {} failed'.format(kwargs['esg_name'])


def delete_monitor(client_session, esg_name, monitor_id):
    """
    This function deletes a monitor on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type monitor_id: str
    :param monitor_id: The Id of the Monitor to be deleted
    :return: Returns True on successful deletion of the Monitor and None on failure or if the ESG was not found
    :rtype: bool
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    result = client_session.delete('lbMonitor', uri_parameters={'edgeId': esg_id, 'monitorID': monitor_id})

    if result['status'] == 204:
        return True
    else:
        return None


def _delete_monitor(client_session, **kwargs):
    needed_params = ['esg_name', 'mon_id']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = delete_monitor(client_session, kwargs['esg_name'], kwargs['mon_id'])

    if result:
        print 'Deleting Monitor {} on esg {} succeeded'.format(kwargs['mon_id'], kwargs['esg_name'])
    else:
        print 'Deleting Monitor {} on esg {} failed'.format(kwargs['mon_id'], kwargs['esg_name'])


def read_monitor(client_session, esg_name, monitor_name):
    """
    This function returns the Id and Details of a Monitor on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type monitor_name: str
    :param monitor_name: The name of the monitor to get the details from
    :return: Returns a tuple, the first item of the tuple contains the Id of the Monitor as a string, the second
             item contains the Monitor details returned from the NSX API as a dict
    :rtype: tuple
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None, None

    mon_list, mon_list_verbose = list_monitors(client_session, esg_name)

    try:
        mon_id = [mon[0] for mon in mon_list if mon[1] == monitor_name][0]
    except IndexError:
        return None, None

    result = client_session.read('lbMonitor', uri_parameters={'edgeId': esg_id, 'monitorID': mon_id})

    mon_id = result['body']['monitor']['monitorId']
    mon_details = result['body']['monitor']

    return mon_id, mon_details


def _read_monitor(client_session, **kwargs):
    needed_params = ['esg_name', 'monitor']
    if not check_for_parameters(needed_params, kwargs):
        return None

    mon_id, mon_details = read_monitor(client_session, kwargs['esg_name'], kwargs['monitor'])

    if kwargs['verbose']:
        print mon_id
    else:
        print 'LB Monitor {} on ESG {} has the Id: {}'.format(kwargs['monitor'], kwargs['esg_name'], mon_id)


def list_monitors(client_session, esg_name):
    """
    This function lists all LB Monitors on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :return: Returns a tuple, the first item containing a list of tuples containing:
             [0] The Id of the Monitor
             [1] The name of the Monitor
             [2] The monitoring interval
             [3] The timeout for the dead declaration
             [4] The maximum retries for a monitor probe
             [5] The monitor type
            The second item contains all monitor details on the system as a list of dicts
    :rtype: tuple
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    mons_api = client_session.read('lbMonitors', uri_parameters={'edgeId': esg_id})['body']

    if mons_api['loadBalancer']:
        if 'monitor' in mons_api['loadBalancer']:
            mons = client_session.normalize_list_return(mons_api['loadBalancer']['monitor'])
        else:
            mons = []
    else:
        mons = []

    mons_lst = [(mon.get('monitorId'), mon.get('name'), mon.get('interval'), mon.get('timeout'),
                 mon.get('maxRetries'), mon.get('type')) for mon in mons]

    mons_lst_verbose = [mon for mon in mons]

    return mons_lst, mons_lst_verbose


def _list_monitors(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    mon_list, mon_list_verbose = list_monitors(client_session, kwargs['esg_name'])

    if kwargs['verbose']:
        print json.dumps(mon_list_verbose)
    else:
        print tabulate(mon_list, headers=["Monitor Id", "Monitor Name", "Interval", "Timeout", "Max retries", "Type"],
                       tablefmt="psql")


def load_balancer(client_session, esg_name, enabled=None, syslog_enabled=None, syslog_level=None, acceleration=None):
    """
    This function enables / disables the load balancing functionality on the ESG and sets the syslog state and level

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :type enabled: bool
    :param enabled: ('true'/'false'), the desired state of the Load Balancer
    :type syslog_enabled: str
    :param syslog_enabled: ('true'/'false'), the desired logging state of the Load Balancer
    :type syslog_level: str
    :param syslog_level: The logging level for Load Balancing on this Edge (INFO/WARNING/etc.)
    :type acceleration: str
    :param acceleration: Is acceleration enabled globaly ('true'/'false')
    :rtype: bool
    :return: Return True on success of the operation
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    change_needed = False

    current_lb_config = client_session.read('loadBalancer', uri_parameters={'edgeId': esg_id})['body']
    new_lb_config = current_lb_config

    if enabled:
        if current_lb_config['loadBalancer']['enabled'] == 'false':
            new_lb_config['loadBalancer']['enabled'] = 'true'
            change_needed = True
    else:
        if current_lb_config['loadBalancer']['enabled'] == 'true':
            new_lb_config['loadBalancer']['enabled'] = 'false'
            change_needed = True

    if syslog_enabled == 'true':
        if current_lb_config['loadBalancer']['logging']['enable'] == 'false':
            new_lb_config['loadBalancer']['logging']['enable'] = 'true'
            change_needed = True
    elif syslog_enabled == 'false':
        if current_lb_config['loadBalancer']['logging']['enable'] == 'true':
            new_lb_config['loadBalancer']['logging']['enable'] = 'false'
            change_needed = True

    if syslog_level:
        if current_lb_config['loadBalancer']['logging']['logLevel'] != syslog_level:
            new_lb_config['loadBalancer']['logging']['logLevel'] = syslog_level
            change_needed = True

    if acceleration == 'true':
        if current_lb_config['loadBalancer']['accelerationEnabled'] == 'false':
            new_lb_config['loadBalancer']['accelerationEnabled'] = 'true'
            change_needed = True
    else:
        if current_lb_config['loadBalancer']['accelerationEnabled'] == 'true':
            new_lb_config['loadBalancer']['accelerationEnabled'] = 'false'
            change_needed = True

    if not change_needed:
        return True
    else:
        result = client_session.update('loadBalancer', uri_parameters={'edgeId': esg_id},
                                       request_body_dict=new_lb_config)
        if result['status'] == 204:
            return True
        else:
            return False


def _enable_lb(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = load_balancer(client_session, kwargs['esg_name'], enabled=True, syslog_enabled=kwargs['logging'],
                           syslog_level=kwargs['log_level'], acceleration=kwargs['acceleration'])

    if not result:
        print 'Enabling Load Balancing on Edge Services Gateway {} failed'.format(kwargs['esg_name'])
    else:
        print 'Enabling Load Balancing on Edge Services Gateway {} succeeded'.format(kwargs['esg_name'])


def _disable_lb(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = load_balancer(client_session, kwargs['esg_name'], enabled=False)

    if not result:
        print 'Disabling Load Balancing on Edge Services Gateway {} failed'.format(kwargs['esg_name'])
    else:
        print 'Disabling Load Balancing on Edge Services Gateway {} succeeded'.format(kwargs['esg_name'])


def show_loadbalancer(client_session, esg_name):
    """
    This function returns the Loadbalancer Configuration and Status

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :return: returns a list of tuples with one list entry, the first item is a tuple with the following items
              [0] The status of the LoadBalancer ('true'/'false')
              [1] The status of the LoadBalancer Syslog ('true'/'false')
              [2] The Syslog logging level for the LB
              [3] The Acceleration status ('true'/'false')
             the second item in the tuple contains the details configuration as a dict as returned from the API
    :rtype: tuple
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    conf_api = client_session.read('loadBalancer', uri_parameters={'edgeId': esg_id})['body']

    if conf_api['loadBalancer']:
        conf = conf_api['loadBalancer']
        conf_log = conf_api['loadBalancer']['logging']
        return [(conf.get('enabled'), conf_log.get('enable'), conf_log.get('logLevel'),
                 conf.get('accelerationEnabled'))], conf_api
    else:
        return None, None


def _show_loadbalancer(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    conf, conf_detail = show_loadbalancer(client_session, kwargs['esg_name'])

    if kwargs['verbose']:
        print json.dumps(conf_detail)
    else:
        print tabulate(conf, headers=["LB Enabled", "LB Syslog Enabled", "LB Syslog Level", "Acceleration"],
                       tablefmt="psql")


def delete_load_balancer(client_session, esg_name):
    """
    This function deletes the load balancer config on an ESG

    :type client_session: nsxramlclient.client.NsxClient
    :param client_session: A nsxramlclient session Object
    :type esg_name: str
    :param esg_name: The display name of a Edge Service Gateway used for Load Balancing
    :return: Returns True on successful deletion of the LB Config and None on failure or if the ESG was not found
    :rtype: bool
    """
    esg_id, esg_params = get_edge(client_session, esg_name)
    if not esg_id:
        return None

    result = client_session.delete('loadBalancer', uri_parameters={'edgeId': esg_id})

    if result['status'] == 204:
        return True
    else:
        return None


def _delete_load_balancer(client_session, **kwargs):
    needed_params = ['esg_name']
    if not check_for_parameters(needed_params, kwargs):
        return None

    result = delete_load_balancer(client_session, kwargs['esg_name'])

    if result:
        print 'Deleting LB Config on esg {} succeeded'.format(kwargs['esg_name'])
    else:
        print 'Deleting LB Config on esg {} failed'.format(kwargs['esg_name'])


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
    add_pool:           Add a server pool on the Load Balancer
    delete_pool:        Deletes a server pool from the Load Balancer
    read_pool:          Read the Pool Id from the Load Balancer
    status_pool:        Displays the Status of the Pool specified
    status_member:      Displays the Status of the Pool Members
    list_pools:         Lists all server pools present on the load balancer
    add_member:         Adds a member to the specified Pool, members can be IP Addresses or VC Objects
    read_member:        Reads the Id of a member from the Pool
    delete_member:      Deletes a member from the Pool
    list_members:       Lists all members in the Pool
    add_vip:            Add a virtual server (VIP) to the Load Balancer
    read_vip:           Reads the Id of a VIP on the Load Balancer
    delete_vip:         Deletes a VIP from the Load Balancer
    list_vips           Lists all VIPs on the Load Balancer
    add_monitor:        Adds a LB Monitor to the Load Balancer
    delete_monitor:     Deletes a LB Monitor from the Load Balancer
    read_monitor:       Reads the Id of a LB monitor on the Load Balancer
    list_monitors:      Lists all LB monitors on the Load Balancer
    enable_lb:          Enables the Load Balancing Service on the ESG
    disable_lb:         Disables the Load Balancing Service on the ESG
    show_lb:            Show the current LB Configuration and Status
    delete_lb:          Delete the complete LB Configuration on the Load Balancer
    """)

    parser.add_argument("-n",
                        "--esg_name",
                        help="ESG name")
    parser.add_argument("-pfn",
                        "--profile_name",
                        help="Application Profile Name")
    parser.add_argument("-pfi",
                        "--profile_id",
                        help="Application Profile Id")
    parser.add_argument("-pr",
                        "--protocol",
                        help="Protocol type (TCP,UDP,HTTP, HTTPS, ICMP), used in Application Profile, VIP and"
                             "Monitor configuration")
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
    parser.add_argument("-u",
                        "--url",
                        help="Application Profile HTTP redirect URL for HTTP Types or URL used for HTTP monitor")
    parser.add_argument("-pon",
                        "--pool_name",
                        help="The name of an Server Pool")
    parser.add_argument("-poi",
                        "--pool_id",
                        help="The Id of an Server Pool (used when deleting)")
    parser.add_argument("-pod",
                        "--pool_description",
                        help="The description of an Server Pool")
    parser.add_argument("-al",
                        "--algorithm",
                        help="The load balancing algorithm for an Server Pool (round-robin, ip-hash, leastconn, uri, "
                             "httpheader, url)")
    parser.add_argument("-alp",
                        "--algorithm_params",
                        help="Additional parameters for the server pool algorithm")
    parser.add_argument("-mt",
                        "--monitor",
                        help="The name of the monitor used for the server pool")
    parser.add_argument("-tp",
                        "--transparent",
                        help="change the mode of the server pool to transparent ('true'/'false')")
    parser.add_argument("-mn",
                        "--member_name",
                        help="The name of a server pool member")
    parser.add_argument("-mi",
                        "--member_id",
                        help="The Id of a server pool member (used when deleting member from Pool)")
    parser.add_argument("-m",
                        "--member",
                        help="The ip address of a server pool member")
    parser.add_argument("-po",
                        "--port",
                        help="UDP/TCP Port used in server pool members and VIPs")
    parser.add_argument("-mop",
                        "--monitor_port",
                        help="The UDP/TCP Port used for monitoring in server pool members")
    parser.add_argument("-wt",
                        "--weight",
                        help="The weight of a server pool members")
    parser.add_argument("-mxc",
                        "--max_conn",
                        help="The maximum connections of a server pool members")
    parser.add_argument("-mic",
                        "--min_conn",
                        help="The minimum connections of a server pool members")
    parser.add_argument("-vn",
                        "--vip_name",
                        help="The name of a virtual server (VIP)")
    parser.add_argument("-vi",
                        "--vip_id",
                        help="The Id of a virtual server (VIP) (used when deleting a VIP)")
    parser.add_argument("-vip",
                        "--vip_ip",
                        help="The IP Address of a virtual server (VIP), this address needs to be the IP of a "
                             "vnic on the ESG")
    parser.add_argument("-vid",
                        "--vip_description",
                        help="A free text description for the virtual server (VIP)")
    parser.add_argument("-cl",
                        "--conn_limit",
                        help="Connection Limit on the virtual server (VIP)")
    parser.add_argument("-cr",
                        "--conn_rate_limit",
                        help="Connection rate Limit on the virtual server (VIP)")
    parser.add_argument("-acc",
                        "--acceleration",
                        default='false',
                        help="Desired Acceleration state ('true'/'false')")
    parser.add_argument("-mon",
                        "--mon_name",
                        help="The name of the LB Monitor to add or read")
    parser.add_argument("-moi",
                        "--mon_id",
                        help="The Id of the LB Monitor to be deleted")
    parser.add_argument("-to",
                        "--timeout",
                        default='15',
                        help="The Timeout value for a LB Monitor")
    parser.add_argument("-iv",
                        "--interval",
                        default='10',
                        help="The Interval value for a LB Monitor")
    parser.add_argument("-mr",
                        "--max_retries",
                        default='3',
                        help="The maximum retries for a LB Monitor")
    parser.add_argument("-mx",
                        "--mon_expected",
                        help="The expected response for a LB Monitor")
    parser.add_argument("-mtd",
                        "--method",
                        help="The method used for a LB Monitor (GET, POST, OPTIONS)")
    parser.add_argument("-snd",
                        "--send",
                        help="The send value for a LB Monitor")
    parser.add_argument("-rcv",
                        "--receive",
                        help="The receive value for a LB Monitor")
    parser.add_argument("-ext",
                        "--extension",
                        help="Extensions for a LB Monitor")
    parser.add_argument("-lg",
                        "--logging",
                        help="Logging status for the Load Balancer (true/false)")
    parser.add_argument("-ll",
                        "--log_level",
                        help="Log level for LB")

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
            'add_pool': _add_pool,
            'read_pool': _read_pool,
            'delete_pool': _delete_pool,
            'list_pools': _list_pools,
            'add_member': _add_member,
            'read_member': _read_member,
            'delete_member': _delete_member,
            'list_members': _list_members,
            'add_vip': _add_vip,
            'read_vip': _read_vip,
            'delete_vip': _delete_vip,
            'list_vips': _list_vips,
            'add_monitor': _add_monitor,
            'delete_monitor': _delete_monitor,
            'read_monitor': _read_monitor,
            'list_monitors': _list_monitors,
            'enable_lb': _enable_lb,
            'disable_lb': _disable_lb,
            'show_lb': _show_loadbalancer,
            'delete_lb': _delete_load_balancer
            }
        command_selector[args.command](client_session, esg_name=args.esg_name, profile_name=args.profile_name,
                                       profile_id=args.profile_id, protocol=args.protocol,
                                       persistence=args.persistence, expire=args.expire, cookie_name=args.cookie_name,
                                       cookie_mode=args.cookie_mode, xforwardedfor=args.xforwardedfor,
                                       url=args.url, pool_name=args.pool_name, acceleration=args.acceleration,
                                       pool_description=args.pool_description, algorithm=args.algorithm,
                                       algorithm_params=args.algorithm_params, transparent=args.transparent,
                                       member_name=args.member_name, port=args.port, monitor_port=args.monitor_port,
                                       monitor=args.monitor, weight=args.weight, max_conn=args.max_conn,
                                       min_conn=args.min_conn, pool_id=args.pool_id, member_id=args.member_id,
                                       member=args.member, vip_name=args.vip_name, vip_ip=args.vip_ip,
                                       conn_limit=args.conn_limit, conn_rate_limit=args.conn_rate_limit,
                                       vip_description=args.vip_description, vip_id=args.vip_id, logging=args.logging,
                                       log_level=args.log_level, mon_name=args.mon_name, mon_id=args.mon_id,
                                       timeout=args.timeout, interval=args.interval, max_retries=args.max_retries,
                                       mon_expected=args.mon_expected, method=args.method, send=args.send,
                                       receive=args.receive, extension=args.extension, verbose=args.verbose)
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
