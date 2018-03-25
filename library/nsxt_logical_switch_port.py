#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2018 VMware, Inc. All Rights Reserved.
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

__author__ = 'yasensim'


import requests, time
try:
    from com.vmware.nsx.model_client import Tag
    from com.vmware.nsx_client import LogicalSwitches
    from com.vmware.nsx.model_client import LogicalSwitch
from com.vmware.nsx_client import LogicalPorts
from com.vmware.nsx.model_client import LogicalPort


    from com.vmware.vapi.std.errors_client import NotFound
    from vmware.vapi.lib import connect
    from vmware.vapi.security.user_password import \
        create_user_password_security_context
    from vmware.vapi.stdlib.client.factories import StubConfigurationFactory
    from com.vmware.nsx.model_client import ApiError
    from com.vmware.vapi.std.errors_client import Error
    HAS_PYNSXT = True
except ImportError:
    HAS_PYNSXT = False

def listLogicalSwitches(module, stub_config):
    ls_list = []
    try:
        ls_svc = LogicalSwitches(stub_config)
        ls_list = ls_svc.list()
    except Error as ex:
        api_error = ex.date.convert_to(ApiError)
        module.fail_json(msg='API Error listing Logical Switches: %s'%(api_error.error_message))
    return ls_list

def getLogicalSwitchByName(module, stub_config):
    result = listLogicalSwitches(module, stub_config)
    for vs in result.results:
        ls = vs.convert_to(LogicalSwitch)
        if ls.display_name == module.params['display_name']:
            return ls
    return None

def main():
    module = AnsibleModule(
        argument_spec=dict(
            display_name=dict(required=True, type='str'),
            description=dict(required=False, type='str', default=None),
            admin_state=dict(required=False, type='str', default='UP', choices=['UP', 'DOWN']),
            ip_pool_id=dict(required=False, type='str', default=None),
            mac_pool_id=dict(required=False, type='str', default=None),
            replication_mode=dict(required=False, type='str', default='MTEP', choices=['MTEP', 'SOURCE']),
            switching_profile_ids=dict(required=False, type='list', default=None),
            transport_zone_id=dict(required=True, type='str'),
            vlan=dict(required=False, type='int', default=None),
            tags=dict(required=False, type='dict', default=None),
            state=dict(required=False, type='str', default="present", choices=['present', 'absent']),
            nsx_manager=dict(required=True, type='str'),
            nsx_username=dict(required=True, type='str'),
            nsx_passwd=dict(required=True, type='str', no_log=True)
        ),
        supports_check_mode=False
    )

    if not HAS_PYNSXT:
        module.fail_json(msg='pynsxt is required for this module')
    session = requests.session()
    session.verify = False
    nsx_url = 'https://%s:%s' % (module.params['nsx_manager'], 443)
    connector = connect.get_requests_connector(
        session=session, msg_protocol='rest', url=nsx_url)
    stub_config = StubConfigurationFactory.new_std_configuration(connector)
    security_context = create_user_password_security_context(module.params["nsx_username"], module.params["nsx_passwd"])
    connector.set_security_context(security_context)
    requests.packages.urllib3.disable_warnings()
    tags=None
    if module.params['tags'] is not None:
        tags = []
        for key, value in module.params['tags'].items():
            tag=Tag(scope=key, tag=value)
            tags.append(tag)
    ls_svc = LogicalSwitches(stub_config)
    ls = getLogicalSwitchByName(module, stub_config)
    if module.params['state'] == 'present':
        if ls is None:
            new_ls = LogicalSwitch(
                display_name=module.params['display_name'],
                description=module.params['description'],
                address_bindings=None,
                admin_state=module.params['admin_state'],
                ip_pool_id=module.params['ip_pool_id'],
                mac_pool_id=module.params['mac_pool_id'],
                replication_mode=module.params['replication_mode'],
                switching_profile_ids=None,
                transport_zone_id=module.params['transport_zone_id'],
                vlan=module.params['vlan'],
                tags=tags
            )
            new_ls = ls_svc.create(new_ls)
            module.exit_json(changed=True, object_name=module.params['display_name'], id=new_ls.id, message="Logical Switch with name %s created!"%(module.params['display_name']))
        elif ls:
            changed = False
            if tags != ls.tags:
                changed = True
                ls.tags=tags
                new_ls = ls_svc.update(ls.id, ls)
            if changed:
                module.exit_json(changed=True, object_name=module.params['display_name'], id=new_ls.id, message="Logical Switch with name %s has changed tags!"%(module.params['display_name']))
            module.exit_json(changed=False, object_name=module.params['display_name'], id=ls.id, message="Logical Switch with name %s already exists!"%(module.params['display_name']))

    elif module.params['state'] == "absent":
        if ls:
            ls_svc.delete(ls.id)
            module.exit_json(changed=True, object_name=module.params['display_name'], message="Logical Switch with name %s deleted!"%(module.params['display_name']))
        module.exit_json(changed=False, object_name=module.params['display_name'], message="Logical Switch with name %s does not exist!"%(module.params['display_name']))

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
