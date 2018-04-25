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
    from com.vmware.nsx.fabric_client import ComputeCollectionFabricTemplates
    from com.vmware.nsx.fabric_client import ComputeCollections
    from com.vmware.nsx.fabric_client import Nodes
    from com.vmware.nsx.model_client import EdgeNode
    from com.vmware.nsx.model_client import EdgeNodeDeploymentConfig
    from com.vmware.nsx.model_client import VsphereDeploymentConfig
    from com.vmware.nsx.model_client import DeploymentConfig
    from com.vmware.nsx.model_client import NodeUserSettings
    from com.vmware.nsx.model_client import IPSubnet
    from com.vmware.nsx.fabric.nodes_client import Status

    from com.vmware.nsx_client import ComputeCollectionTransportNodeTemplates

    from com.vmware.nsx.model_client import ComputeCollectionFabricTemplate
    from com.vmware.nsx.model_client import ComputeCollection
    from com.vmware.nsx.model_client import ComputeCollectionTransportNodeTemplate
    from com.vmware.nsx.model_client import StandardHostSwitchSpec
    from com.vmware.nsx.model_client import StandardHostSwitch
    from com.vmware.nsx.model_client import IpAssignmentSpec

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

def getComputeByName(module, stub_config):
    compute_id = ""
    cc_svc = ComputeCollections(stub_config)
    cc_list = cc_svc.list()
    for cc in cc_list.results:
        if cc.display_name == module.params['vsphere_cluster']:
            return cc
    module.fail_json(msg="No Cluster with name %s found!" % (module.params['vsphere_compute']))

def createDeploymentConfig(module, stub_config):
    compute = getComputeByName(module, stub_config)
    vsphereDeploymentConfig = VsphereDeploymentConfig(
                 compute_id=compute.external_id,
                 data_network_ids=module.params['data_network_ids'],
                 default_gateway_addresses=module.params['default_gateway_addresses'],
                 host_id=module.params['host_id'],
                 hostname=module.params['hostname'],
                 management_network_id=module.params['management_network_id'],
                 management_port_subnets=[IPSubnet(ip_addresses=[module.params['management_port_subnet']], prefix_length=module.params['management_port_prefix'])],
                 storage_id=module.params['storage_id'],
                 vc_id=module.params['vc_id'],
                 placement_type='VsphereDeploymentConfig'
    )

    edgeNodeDeploymentConfig = EdgeNodeDeploymentConfig(
		form_factor = module.params['form_factor'],
		node_user_settings = NodeUserSettings(
		    cli_password = module.params['cli_password'],
		    root_password = module.params['root_password']
		),
		vm_deployment_config = vsphereDeploymentConfig
    )
    return edgeNodeDeploymentConfig
def createEdge(module, stub_config):

    nodes_svc = Nodes(stub_config)



    edgeNode = EdgeNode(
                 deployment_config = createDeploymentConfig(module, stub_config),
                 description = module.params['description'],
                 display_name = module.params['display_name'],
                 tags = None
    )
    try:
        tmp_node = nodes_svc.create(edgeNode)
        node = tmp_node.convert_to(EdgeNode)
        status_svc = Status(stub_config)
        while True:
            node_status = status_svc.get(node.id)
            time.sleep(5)
            if node_status.mpa_connectivity_status == 'UP' and node_status.host_node_deployment_status == 'NODE_READY':
                module.exit_json(changed=True, id=node.id, msg="Edge VM with name %s created!" % (module.params['display_name']))
    except Error as ex:
        api_error = ex.data.convert_to(ApiError)
        module.fail_json('API Error creating node: %s' % (api_error.error_message))

def getEdheNodeByName(module, stub_config):
    nodes_svc = Nodes(stub_config)
    nodes_list = nodes_svc.list(resource_type='EdgeNode')
    for node in nodes_list.results:
        en = node.convert_to(EdgeNode)
        if en.display_name == module.params['display_name']:
            return en
    return None

def main():
    module = AnsibleModule(
        argument_spec=dict(
            display_name=dict(required=True, type='str'),
            description=dict(required=False, type='str', default=None),
            form_factor=dict(required=False, type='str', default='MEDIUM', choices=['SMALL', 'MEDIUM', 'LARGE']),
            vsphere_cluster=dict(required=True, type='str'),
            host_id=dict(required=False, type='str', default=None),
            data_network_ids=dict(required=True, type='list'),
            default_gateway_addresses=dict(required=True, type='list'),
            hostname=dict(required=True, type='str'),
            management_network_id=dict(required=True, type='str'),
            management_port_subnet=dict(required=True, type='str'),
            management_port_prefix=dict(required=True, type='int'),
            storage_id=dict(required=True, type='str'),
            vc_id=dict(required=True, type='str'),
            cli_password=dict(required=True, type='str', no_log=True),
            root_password=dict(required=True, type='str', no_log=True),
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
    node = getEdheNodeByName(module, stub_config)
    if module.params['state'] == "present":
        if node:
            module.exit_json(changed=False, id=node.id, msg="Edge with name %s already exists!" % (module.params['display_name']))
        elif not node:
            createEdge(module, stub_config)





    elif module.params['state'] == "absent":
        if node:
            nodes_svc = Nodes(stub_config)
            nodes_svc.delete(node.id)
            module.exit_json(changed=True, object_name=module.params['display_name'], message="Node with name %s deleted"%(module.params['display_name']))
        elif not node:
            module.exit_json(changed=False, object_name=module.params['display_name'], message="Node with name %s does not exists"%(module.params['display_name']))




from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
