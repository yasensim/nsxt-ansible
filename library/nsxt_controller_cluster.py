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

    from com.vmware.nsx.cluster.nodes_client import Deployments
    from com.vmware.nsx.cluster.nodes.deployments_client import Status
    from com.vmware.nsx.model_client import ClusterNodeVMDeploymentStatusReport

    from com.vmware.nsx.model_client import AddClusterNodeVMInfo
    from com.vmware.nsx.model_client import ControlClusteringConfig
    from com.vmware.nsx.model_client import VsphereClusterNodeVMDeploymentConfig
    from com.vmware.nsx.model_client import ClusterNodeVMDeploymentRequest
    from com.vmware.nsx.model_client import ClusterNodeVMDeploymentRequestList
    from com.vmware.nsx.model_client import NodeUserSettings
    from com.vmware.nsx.model_client import IPSubnet
    from com.vmware.nsx.fabric_client import ComputeCollections
    from com.vmware.nsx.model_client import ComputeCollection
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

def getComputeByName(controller, stub_config):
    compute_id = ""
    cc_svc = ComputeCollections(stub_config)
    cc_list = cc_svc.list()
    for cc in cc_list.results:
        if cc.display_name == controller['vsphere_cluster']:
            return cc
    module.fail_json(msg="No Cluster with name %s found!" % (controller['vsphere_cluster']))


def createController(controller, stub_config):
    compute = getComputeByName(controller, stub_config)
    vsphereClusterNodeVMDeploymentConfig = VsphereClusterNodeVMDeploymentConfig(
                 compute_id=compute.external_id,
                 default_gateway_addresses=controller['default_gateway_addresses'],
                 host_id=controller['host_id'],
                 hostname=controller['hostname'],
                 management_network_id=controller['management_network_id'],
                 management_port_subnets=[IPSubnet(ip_addresses=[controller['management_port_subnet']], prefix_length=int(controller['management_port_prefix']))],
                 storage_id=controller['storage_id'],
                 vc_id=controller['vc_id'],
                 allow_ssh_root_login=controller['allow_ssh_root_login'],
                 enable_ssh=controller['enable_ssh'],
                 placement_type='VsphereClusterNodeVMDeploymentConfig'
    )


    clusterNodeVMDeploymentRequest = ClusterNodeVMDeploymentRequest(
	deployment_config=vsphereClusterNodeVMDeploymentConfig, 
	form_factor=controller['form_factor'], 
	roles=['CONTROLLER'], 
	user_settings = NodeUserSettings(
			    cli_password = controller['cli_password'],
			    root_password = controller['root_password']
			),
	vm_id=None
    )
    return clusterNodeVMDeploymentRequest


def main():
    module = AnsibleModule(
        argument_spec=dict(
            shared_secret=dict(required=True, type='str', no_log=True),
            controllers=dict(required=True, type='list'),
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
    d_svc = Deployments(stub_config)
    dep_list = d_svc.list()
    ctrl_list = []

    if module.params['state'] == "present":
        isExisting = False
        for controller in module.params['controllers']:
            isExistingTmp = False
            for deploymentRequest in dep_list.results:
                dconfig = deploymentRequest.deployment_config.convert_to(VsphereClusterNodeVMDeploymentConfig)
                if controller['hostname'] == dconfig.hostname:
                    isExistingTmp = True
                    isExisting = True
            if not isExistingTmp:
                ctrl_list.append(createController(controller, stub_config))

        controlClusteringConfig = ControlClusteringConfig(
	    join_to_existing_cluster=isExisting, 
	    shared_secret=module.params['shared_secret'], 
	    clustering_type='ControlClusteringConfig'
        )
        addClusterNodeVMInfo = AddClusterNodeVMInfo(
            clustering_config=controlClusteringConfig, 
            deployment_requests=ctrl_list
        )
        check = 0
        elif not isExisting:
            check = len(module.params['controllers'])-1

        try:
            deploy = d_svc.create(addClusterNodeVMInfo)
            cluster = deploy.convert_to(ClusterNodeVMDeploymentRequestList)
            status_svc = Status(stub_config)
            while True:
                time.sleep(5)
                node_status = status_svc.get(cluster.results[check].vm_id)
                status = node_status.convert_to(ClusterNodeVMDeploymentStatusReport)
                if status.status == 'VM_CLUSTERING_SUCCESSFUL':
                    time.sleep(5)
                    module.exit_json(changed=True, degug=str(cluster), msg="Controll Cluster created")
                if status.failure_message:
                    module.fail_json(msg="Error: %s " % (status.failure_message))

        except Error as ex:
            api_error = ex.data.convert_to(ApiError)
            module.fail_json('API Error creating node: %s' % (api_error.error_message))

    elif module.params['state'] == "absent":
        changed = False
        for controller in module.params['controllers']:
            isExistingTmp = False
            for deploymentRequest in dep_list.results:
                dconfig = deploymentRequest.deployment_config.convert_to(VsphereClusterNodeVMDeploymentConfig)
                if controller['hostname'] == dconfig.hostname:
                    d_svc.delete(deploymentRequest.vm_id, force_delete=True)
                    changed = True
                    time.sleep(5)
        time.sleep(40)
        module.exit_json(changed=changed, message="Deletion of controll cluster nodes")

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
