#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2018 VMware, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
# either express or implied. See the License for the specific language governing permissions and limitations under the License.


__author__ = 'yasensim'


import requests, time
try:
    from com.vmware.nsx.model_client import Tag
    from com.vmware.nsx_client import LogicalSwitches
    from com.vmware.nsx.model_client import LogicalSwitch
    from com.vmware.nsx.model_client import TransportZone
    from com.vmware.nsx_client import TransportZones

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

def listTransportZones(module, stub_config):
    tz_list = []
    try:
        tz_svc = TransportZones(stub_config)
        tz_list = tz_svc.list()
    except Error as ex:
        api_error = ex.date.convert_to(ApiError)
        module.fail_json(msg='API Error listing Transport Zones: %s'%(api_error.error_message))
    return tz_list

def getTransportZoneByName(module, stub_config):
    result = listTransportZones(module, stub_config)
    for vs in result.results:
        tz = vs.convert_to(TransportZone)
        if tz.display_name == module.params['transport_zone_name']:
            return tz
    return None

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
            transport_zone_id=dict(required=False, type='str'),
            transport_zone_name=dict(required=False, type='str'),
            vlan=dict(required=False, type='int', default=None),
            tags=dict(required=False, type='dict', default=None),
            state=dict(required=False, type='str', default="present", choices=['present', 'absent']),
            nsx_manager=dict(required=True, type='str'),
            nsx_username=dict(required=True, type='str'),
            nsx_passwd=dict(required=True, type='str', no_log=True)
        ),
        supports_check_mode=True
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
    if not module.params['transport_zone_id']:
        tz = getTransportZoneByName(module, stub_config)
        module.params['transport_zone_id'] = tz.id

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
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(new_ls), id="1111")
            new_ls = ls_svc.create(new_ls)
#
#  TODO: Check the realisation before exiting !!!!
#
            module.exit_json(changed=True, object_name=module.params['display_name'], id=new_ls.id, message="Logical Switch with name %s created!"%(module.params['display_name']))
        elif ls:
            changed = False
            if tags != ls.tags:
                changed = True
                ls.tags=tags
                if module.check_mode:
                    module.exit_json(changed=True, debug_out=str(ls), id=ls.id)
                new_ls = ls_svc.update(ls.id, ls)
            if changed:
                module.exit_json(changed=True, object_name=module.params['display_name'], id=new_ls.id, message="Logical Switch with name %s has changed tags!"%(module.params['display_name']))
            module.exit_json(changed=False, object_name=module.params['display_name'], id=ls.id, message="Logical Switch with name %s already exists!"%(module.params['display_name']))

    elif module.params['state'] == "absent":
        if ls:
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(ls), id=ls.id)
            ls_svc.delete(ls.id)
            module.exit_json(changed=True, object_name=module.params['display_name'], message="Logical Switch with name %s deleted!"%(module.params['display_name']))
        module.exit_json(changed=False, object_name=module.params['display_name'], message="Logical Switch with name %s does not exist!"%(module.params['display_name']))

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
