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
    from com.vmware.nsx.model_client import IpBlock
    from com.vmware.nsx.model_client import Tag

    from com.vmware.nsx.pools_client import IpBlocks

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

def listIpBlocks(module, stub_config):
    ipblock_list = []
    try:
        ipblock_svc = IpBlocks(stub_config)
        ipblock_list = ipblock_svc.list()
    except Error as ex:
        api_error = ex.date.convert_to(ApiError)
        module.fail_json(msg='API Error listing IP BLOCKS: %s'%(api_error.error_message))
    return ipblock_list

def getIpBlockByName(module, stub_config):
    result = listIpBlocks(module, stub_config)
    for vs in result.results:
        ipblock = vs.convert_to(IpBlock)
        if ipblock.display_name == module.params['display_name']:
            return ipblock
    return None

def main():
    module = AnsibleModule(
        argument_spec=dict(
            display_name=dict(required=True, type='str'),
            description=dict(required=False, type='str', default=None),
            cidr=dict(required=True, type='str'),
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



    ipblock_svc = IpBlocks(stub_config)
    ipblock = getIpBlockByName(module, stub_config)
    if module.params['state'] == 'present':
        if ipblock is None:
            if module.params['state'] == "present":
                new_ipblock = IpBlock(
                    display_name=module.params['display_name'],
                    description=module.params['description'],
                    cidr=module.params['cidr'],
                    tags=tags
                )
                if module.check_mode:
                    module.exit_json(changed=True, debug_out=str(new_ipblock), id="1111")
                new_ipblock = ipblock_svc.create(new_ipblock)
                module.exit_json(changed=True, object_name=module.params['display_name'], id=new_ipblock.id, message="IP BLOCK with name %s created!"%(module.params['display_name']))
        elif ipblock:
            changed = False
            if tags != ipblock.tags:
                changed = True
                ipblock.tags=tags
            if ipblock.cidr != module.params['cidr']:
                ipblock.cidr = module.params['cidr']
                changed = True
            if changed:
                if module.check_mode:
                    module.exit_json(changed=True, debug_out=str(ipblock), id=ipblock.id)
                new_ipblock = ipblock_svc.update(ipblock.id, ipblock)
                module.exit_json(changed=True, object_name=module.params['display_name'], id=ipblock.id, msg="IP Block has been changed")
            module.exit_json(changed=False, object_name=module.params['display_name'], id=ipblock.id, message="IP Block with name %s already exists!"%(module.params['display_name']))

    elif module.params['state'] == "absent":
        if ipblock:
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(ipblock), id=ipblock.id)
            ipblock_svc.delete(ipblock.id)
            module.exit_json(changed=True, object_name=module.params['display_name'], message="IP Block with name %s deleted!"%(module.params['display_name']))
        module.exit_json(changed=False, object_name=module.params['display_name'], message="IP Block with name %s does not exist!"%(module.params['display_name']))

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
