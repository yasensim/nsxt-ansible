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

import ssl
import socket
import hashlib
import requests, time
try:
    from com.vmware.nsx.fabric_client import ComputeManagers
    from com.vmware.nsx.model_client import ComputeManager
    from com.vmware.nsx.model_client import UsernamePasswordLoginCredential

    from com.vmware.nsx.fabric.compute_managers_client import Status

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

def get_thumb(module):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    wrappedSocket = ssl.wrap_socket(sock)

    try:
        wrappedSocket.connect((module.params['server'], 443))
    except:
        response = False
    else:
        der_cert_bin = wrappedSocket.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(wrappedSocket.getpeercert(True))
    thumb_md5 = hashlib.md5(der_cert_bin).hexdigest()
    thumb_sha1 = hashlib.sha1(der_cert_bin).hexdigest()
    thumb_sha256 = hashlib.sha256(der_cert_bin).hexdigest()
#    print("MD5: " + thumb_md5)
#    print("SHA1: " + thumb_sha1)
#    print("SHA256: " + thumb_sha256.upper())
    sha = thumb_sha256.upper()
    sha = ":".join(sha[i:i+2] for i in range(0, len(sha), 2))
#    print(sha)
    wrappedSocket.close()
    return sha

def listComputeManagers(module, stub_config):
    try:
        cm_svc = ComputeManagers(stub_config)
    except Error as ex:
        api_error = ex.data.convert_to(ApiError)
        module.fail_json(msg='API Error listing Compute Managers: %s'%(api_error.error_message))
    return cm_svc.list()


def createComputeManager(module, stub_config):
    cm_svc = ComputeManagers(stub_config)
    if module.params['thumbprint'] == 'x':
        module.params['thumbprint'] = get_thumb(module)
    newNode = ComputeManager(
	display_name=module.params['display_name'],
	server=module.params['server'],
	origin_type=module.params['origin_type'],
	credential=UsernamePasswordLoginCredential(
            username=module.params['username'], 
            password=module.params['passwd'], 
            thumbprint=module.params['thumbprint']
        )
    )
    if module.check_mode:
        module.exit_json(changed=True, debug_out=str(newNode), id="1111")
    try:
        cm_svc.create(newNode)
    except Error as ex:
        api_error = ex.data.convert_to(ApiError)
        module.fail_json(msg='API Error creating Compute Manager: %s'%(api_error.error_message))
    time.sleep(20)
    resultCm = getCMByName(module, stub_config)
    status_svc = Status(stub_config)
    while True:
        cm_status = status_svc.get(resultCm.id)
        if cm_status.connection_status == "CONNECTING":
            time.sleep(5)
        elif cm_status.connection_status == "UP":
            return resultCm
        else:
            module.fail_json(msg='Error in Compute Manager status: %s'%(str(fn_status)))


def deleteCm(module, cm, stub_config):
    cm_svc = ComputeManagers(stub_config)
    cm_id = cm.id
    cm_name = cm.display_name
    try:
        cm_svc.delete(cm_id)
    except Error as ex:
        api_error = ex.data.convert_to(ApiError)
        module.fail_json(msg='API Error Deleting node: %s'%(api_error.error_message))
    status_svc = Status(stub_config)
    while True:
        try:
            fn_status = status_svc.get(cm_id)
            time.sleep(10)
        except Error as ex:
            module.exit_json(changed=True, object_id=cm_id, object_name=cm_name, msg="Compute Manager Deleted")


def getCMByName(module, stub_config):
    result = listComputeManagers(module, stub_config)
    for vs in result.results:
        cm = vs.convert_to(ComputeManager)
        if cm.display_name == module.params['display_name']:
            return cm
    return None

def main():
    module = AnsibleModule(
        argument_spec=dict(
            display_name=dict(required=True, type='str'),
            server=dict(required=True, type='str'),
            username=dict(required=False, type='str'),
            passwd=dict(required=False, type='str', no_log=True),
            thumbprint=dict(required=False, type='str', default="x", no_log=True),
            origin_type=dict(required=False, type='str', default ='vCenter', choices=['vCenter']),
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

    if module.params['state'] == "present":
        cm = getCMByName(module, stub_config)
        if cm is None:
            result = createComputeManager(module, stub_config)
            module.exit_json(changed=True, id=result.id, object_name=module.params['display_name'], body=str(result))
        else:
            module.exit_json(changed=False, id=cm.id, object_name=module.params['display_name'], message="Compute Manager with name %s already exists!"%(module.params['display_name']))

    elif module.params['state'] == "absent":
        cm = getCMByName(module, stub_config)
        if cm is None:
            module.exit_json(changed=False, object_name=module.params['display_name'], message="No Compute Manager with name %s"%(module.params['display_name']))
        else:
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(cm), id=cm.id)
            deleteCm(module, cm, stub_config)
            module.exit_json(changed=True, object_name=module.params['display_name'], message="Compute Manager with name %s deleted"%(module.params['display_name']))




from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
