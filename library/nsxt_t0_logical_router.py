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
    from com.vmware.nsx.model_client import LogicalRouter
    from com.vmware.nsx_client import LogicalRouters
    from com.vmware.nsx_client import LogicalRouterPorts
    from com.vmware.nsx.model_client import LogicalRouterPort
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

def listLogicalRouters(module, stub_config):
    lr_list = []
    try:
        lr_svc = LogicalRouters(stub_config)
        lr_list = lr_svc.list()
    except Error as ex:
        api_error = ex.date.convert_to(ApiError)
        module.fail_json(msg='API Error listing Logical Routers: %s'%(api_error.error_message))
    return lr_list

def getLogicalRouterByName(module, stub_config):
    result = listLogicalRouters(module, stub_config)
    for vs in result.results:
        lr = vs.convert_to(LogicalRouter)
        if lr.display_name == module.params['display_name']:
            return lr
    return None

def deleteAllPortsOnRouter(lr, module, stub_config):
    lrp_svc = LogicalRouterPorts(stub_config)
    lrpList = lrp_svc.list(logical_router_id=lr.id)
    if lrpList.results:
        for vs in lrpList.results:
            lrp = vs.convert_to(LogicalRouterPort)
            lrp_svc.delete(lrp.id, force=True)



def main():
    module = AnsibleModule(
        argument_spec=dict(
            display_name=dict(required=True, type='str'),
            description=dict(required=False, type='str', default=None),
            failover_mode=dict(required=False, type='str', default=None, choices=['NON_PREEMPTIVE', 'PREEMPTIVE']),
            edge_cluster_id=dict(required=False, type='str', default=None),
            high_availability_mode=dict(required=False, type='str', default='ACTIVE_STANDBY', choices=['ACTIVE_STANDBY', 'ACTIVE_ACTIVE']),
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
    lr_svc = LogicalRouters(stub_config)
    lr = getLogicalRouterByName(module, stub_config)
    if module.params['state'] == 'present':
        if lr is None:
            new_lr = LogicalRouter(
                display_name=module.params['display_name'],
                description=module.params['description'],
                failover_mode=module.params['failover_mode'],
                edge_cluster_id=module.params['edge_cluster_id'],
                router_type='TIER0',
                high_availability_mode=module.params['high_availability_mode'],
                tags=tags
            )
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(new_lr), id="1111")
            try:
                new_lr = lr_svc.create(new_lr)
                module.exit_json(changed=True, object_name=module.params['display_name'], id=new_lr.id, message="Logical Router with name %s created!"%(module.params['display_name']))
            except Error as ex:
                module.fail_json(msg='API Error listing Logical Routers: %s'%(str(ex)))
        elif lr:
            if tags != lr.tags:
                lr.tags=tags
                if module.check_mode:
                    module.exit_json(changed=True, debug_out=str(lr), id=lr.id)
                new_lr = lr_svc.update(lr.id, lr)
                module.exit_json(changed=True, object_name=module.params['display_name'], id=new_lr.id, message="Logical Router with name %s has changed tags!"%(module.params['display_name']))
            module.exit_json(changed=False, object_name=module.params['display_name'], id=lr.id, message="Logical Router with name %s already exists!"%(module.params['display_name']))

    elif module.params['state'] == "absent":

        if lr:
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(lr), id=lr.id)
            try:
                deleteAllPortsOnRouter(lr, module, stub_config)
                lr_svc.delete(lr.id)
            except Error as ex:
                api_error = ex.date.convert_to(ApiError)
                module.fail_json(msg='API Error deleting Logical Routers: %s'%(api_error.error_message))

            module.exit_json(changed=True, object_name=module.params['display_name'], message="Logical Router with name %s deleted!"%(module.params['display_name']))
        module.exit_json(changed=False, object_name=module.params['display_name'], message="Logical Router with name %s does not exist!"%(module.params['display_name']))

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
