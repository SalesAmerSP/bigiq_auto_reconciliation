#!/usr/bin/env python3

import requests
import time
import json
import logging
logger = logging.getLogger(__name__)


def global_token_auth():
    global auth_token
    global auth_token_expiry
    try:
        auth_token
        auth_token_expiry
    except NameError:
        logger.info('auth_token or auth_token_expiry not found; creating variables with dummy values\n')
        auth_token = "null"
        auth_token_expiry = 0
    # Check if current epoch time is less than token expiry;
    # skip token generation if not
    if (time.time() < auth_token_expiry):
        remaining_seconds = auth_token_expiry - time.time()
        logger.info(f'Existing authentication token is still valid. Expires in {remaining_seconds} seconds.\n')
        return
    # request a new token
    url = 'https://' + host + '/mgmt/shared/authn/login'
    payload = {'username': username, 'password': password, 'provider': 'tmos'}
    headers = {'Content-type': 'application/json'}
    logger.info(f'Token API call: {url}, {headers}, {username}\n')
    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error(f"Error making API call: {e} (Endpoint Response: {response.text})\n")
        SystemExit()
    auth_token = response.json()['token']['token']
    auth_token_expiry = response.json()['token']['exp']
    logger.info(f'Auth token retrieved with expiration of {auth_token_expiry} epoch time\n')


def bigiq_http_get(uri, params):
    global_token_auth()
    url = 'https://' + host + '/' + uri
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.info(f'BIG-IQ HTTP GET {headers} {url} {params}\n')
    try:
        response = requests.get(
            url,
            headers=headers,
            params=params
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error(f"Error making API call: {e} (Endpoint Response: {response.text})\n")
        return None
    logger.info(f'BIG-IP API Response: {response.text}\n')
    return response


def bigiq_http_post(uri, payload):
    global_token_auth()
    url = 'https://' + host + '/' + uri
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.info(f'BIG-IQ HTTP POST {headers} {url} {payload}\n')
    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error(f"Error making API call: {e} (Endpoint Response: {response.text})\n")
        return None
    logger.info(f'BIG-IP API Response: {response.text}\n')
    return response


def bigiq_http_patch(uri, payload):
    global_token_auth()
    url = 'https://' + host + '/' + uri
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.info(f'BIG-IQ HTTP PATCH {headers} {url} {payload}\n')
    try:
        response = requests.patch(
            url,
            headers=headers,
            json=payload
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error(f"Error making API call: {e} (Endpoint Response: {response.text})\n")
        return None
    logger.info(f'BIG-IP API Response: {response.text}\n')
    return response


def verify_no_running_device_import_tasks():
    # Ensure no running device import tasks sorting by newest Update timestamp
    api_params = {
        '$orderby': 'lastUpdateMicros desc',
        '$skip': 0,
        '$top': 1
    }
    last_import_task = bigiq_http_get(
        '/mgmt/cm/global/tasks/device-discovery-import-controller',
        api_params
        )
    try:
        last_import_task.json()['items'][0]['status']
    except NameError as e:
        logger.error(f"Error {e}\n")
        SystemExit()
    if last_import_task.json()['items'][0]['status'] == 'RUNNING':
        logger.error('Unexpected running task: ' + last_import_task.text + '\n')
        SystemExit()

    # Ensure no running device import tasks sorting by newest Start timestamp
    api_params = {
        '$orderby': 'startDateTime desc',
        '$skip': 0,
        '$top': 1
    }
    last_import_task = bigiq_http_get(
        '/mgmt/cm/global/tasks/device-discovery-import-controller',
        api_params
        )
    try:
        last_import_task.json()['items'][0]['status']
    except NameError as e:
        logger.error(f"Error {e}\n")
        SystemExit()
    if last_import_task.json()['items'][0]['status'] == 'RUNNING':
        logger.error('Unexpected running task: ' + last_import_task.text + '\n')
        SystemExit()


def verify_no_running_device_deletion_tasks():
    api_params = {
        '$orderby': 'lastUpdateMicros desc',
        '$skip': 0,
        '$top': 1
    }
    last_device_deletion_task = bigiq_http_get(
        '/mgmt/cm/global/tasks/device-remove-trust',
        api_params
    )
    try:
        last_device_deletion_task.json()['items'][0]['status']
    except NameError as e:
        logger.error(f"Error {e}\n")
        SystemExit()
    if last_device_deletion_task.json()['items'][0]['status'] == 'RUNNING':
        logger.error(f'Unexpected running task: {last_device_deletion_task.text}\n')
        SystemExit()


def verify_no_running_agent_install_tasks():
    # Ensure no active agent install tasks
    api_params = {
        '$orderby': 'lastUpdateMicros desc',
        '$skip': 0,
        '$top': 1
    }
    last_agent_install_task = bigiq_http_get(
      '/mgmt/cm/shared/stats-mgmt/agent-install-and-config-task',
      api_params
    )
    try:
        last_agent_install_task.json()['items'][0]['status']
    except NameError as e:
        logger.error(f'Error {e}\n')
        SystemExit()
    if last_agent_install_task.json()['items'][0]['status'] == 'RUNNING':
        logger.error(f'Running task: {last_agent_install_task.text}\n')
        SystemExit()


def retrieve_device_list():
    # Gather a list of all devices and provisioned modules
    api_payload = json.loads('{"multiStageQueryRequest":{"repeatLastStageUntilTerminated":false,"queryParamsList":[{"description":"retrieval","filterProcessorReference":{"link":"https://localhost/mgmt/shared/resolver/device-groups/cm-bigip-allBigIpDevices/devices?%24filter=product%20eq%20\'BIG-IP\'&%24orderby=hostname%20asc%2Caddress%20asc"},"pipelineAction":"DATA_RETRIEVAL","runStageInternally":false},{"description":"pagination","managedPipelineWorkerName":"page-pipe","jsonContext":{"skip":0,"top":5000},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/system/machineid-resolver","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/system/machineid-resolver"},"joinConditions":"machineId=machineId","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"sameDevices"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/global/tasks/device-remove-mgmt-authority?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/global/tasks/device-remove-mgmt-authority?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage"},"joinConditions":"selfLink=deviceReference/link","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"rmaTasks"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/global/tasks/device-remove-trust?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/global/tasks/device-remove-trust?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage"},"joinConditions":"selfLink=deviceReference/link","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"removeTrustTasks"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/shared/stats-mgmt/agent-install-and-config-task?%24orderby=lastUpdateMicros%20desc&%24select=targetDeviceReference%2Cstatus%2CerrorMessage","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/shared/stats-mgmt/agent-install-and-config-task?%24orderby=lastUpdateMicros%20desc&%24select=targetDeviceReference%2Cstatus%2CerrorMessage"},"joinConditions":"selfLink=targetDeviceReference/link","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"agentTasksList"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/shared/stats-mgmt/stats-configuration?%24select=machineId%2Cmodules","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/shared/stats-mgmt/stats-configuration?%24select=machineId%2Cmodules"},"joinConditions":"machineId=machineId","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"statsConfigInfo"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/shared/current-config/sys/provision?%24select=name%2CdeviceReference&%24filter=level%20ne%20\'none\'","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/shared/current-config/sys/provision?%24select=name%2CdeviceReference&%24filter=level%20ne%20\'none\'"},"joinConditions":"machineId=deviceReference/machineId","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"provisioningInfo"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"stats","managedPipelineWorkerName":"resource-stats-pipe","pipelineAction":"DATA_PROCESSING","runStageInternally":false}]},"getOnPostAndTerminate":true,"isPerformanceBoostingEnabled":false}')
    device_list = bigiq_http_post(
        '/mgmt/shared/pipeline/manager/BIG-IP-Devices-Pipeline',
        api_payload
    )
    return device_list


def rediscover_devices(device_list):
    rediscovered_devices = []
    # Parse Devices and Re-discover/Re-import
    for current_device in device_list.json()['items']:
        logger.info('Attempting to rediscover ' + current_device['hostname'])
        try:    # check for device trust
            device_modules_provisioned = current_device['sameDevices'][0]['properties']['cm:gui:module']
        except NameError as e:
            logger.error(f'Device trust is not established; aborting: {e}')
            return
        # Retrieve existing discovery task for reuse
        api_params = {
            '$filter': 'deviceReference/link eq \'*' + current_device['machineId'] + '\''
        }
        existing_discovery_task = bigiq_http_get(
            '/mgmt/cm/global/tasks/device-discovery',
            api_params
        )
        # Compile a list of modules to discover based on pre-discovered modules
        module_discovery_list = []
        for key, value in bigip_discovery_module_mapping.items():
            if key in device_modules_provisioned:
                module_discovery_list.append({'module': value})
        logger.info(f'{current_device['hostname']} has the following modules: {module_discovery_list}\n')
        # Check for existing discovery tasks; skip if not discovered before; reuse existing if found
        if existing_discovery_task.json()['totalItems'] == 0:
            logger.warning('Device has never been discovered; skipping\n')
        elif existing_discovery_task.json()['totalItems'] >= 1:
            existing_discovery_task_id = existing_discovery_task.json()['items'][0]['id']
            existing_discovery_task_api_payload = {
                'moduleList': module_discovery_list,
                'status': 'STARTED'
            }
            reused_discovery_task = bigiq_http_patch(
                'mgmt/cm/global/tasks/device-discovery/' + existing_discovery_task_id,
                existing_discovery_task_api_payload
            )
            executed_task_id = reused_discovery_task.json()['id']
            executed_task_status_text = reused_discovery_task.json()['status']
        while (executed_task_status_text == 'STARTED'):
            api_params = {}
            executed_task_status = bigiq_http_get(
                '/mgmt/cm/global/tasks/device-discovery/'
                + executed_task_id,
                api_params
            )
            executed_task_status_text = (
                executed_task_status.json()['status']
            )
        if executed_task_status_text == "FINISHED":
            logger.info(f'{current_device['hostname']} successfully rediscovered!\n')
            rediscovered_devices.append(current_device)


def reimport_devices(device_list):
    for current_device in device_list:
        # Compile a list of modules to discover based on pre-discovered modules
        device_modules_provisioned = current_device['sameDevices'][0]['properties']['cm:gui:module']
        module_import_list = []
        for key, value in bigip_import_module_mapping.items():
            if key in device_modules_provisioned:
                module_import_list.append({'module': value})
        for current_module in module_import_list:
            api_payload = {
                'createChildTasks': False,
                'skipDiscovery': True,
                'deviceReference': {
                    "link": current_device['selfLink']
                },
                'snapshotWorkingConfig': False,
                'useBigiqSync': False,
                'name': 'reimport-adc_core_' + time.time_ns()
            }
            rediscover_task = bigiq_http_post(
                '/mgmt/cm/' + current_module + '/tasks/declare-mgmt-authority',
                api_payload
            )
            rediscover_task_id = rediscover_task.json()['id']
            rediscover_task_status_text = rediscover_task.json()['status']
            while rediscover_task_status_text == 'STARTED':
                api_params = {}
                rediscover_task_status = bigiq_http_get(
                    '/mgmt/cm/' + current_module + '/tasks/declare -mgmt-authority/' + rediscover_task_id,
                    api_params
                )
                rediscover_task_status_text = rediscover_task_status.json()['status']


def main():
    # Configure logging
    logging.basicConfig(filename="reconcile.log", level=logging.INFO)
    # Define BIG-IQ environment variables
    global username
    global password
    global host
    global bigip_discovery_module_mapping
    global bigip_import_module_mapping
    username = 'admin'
    password = 'mypassword'
    host = 'mybigiq.domain.local'
    bigip_discovery_module_mapping = {
        'adc': 'adc_core',
        'networksecurity': 'firewall',
        'sslo': 'sslo',
        'sharedsecurity': 'security_shared',
        'asmsecurity': 'asm',
        'dns': 'dns',
        'fpsfraudprotectionsecurity': 'fps',
        'Access': 'access'
    }
    logger.info(f'BIG-IP Discovery Module Mapping: {bigip_discovery_module_mapping}')
    bigip_import_module_mapping = {
        'adc': 'adc_core',
        'networksecurity': 'firewall',
        'sharedsecurity': 'security_shared',
        'asmsecurity': 'asm',
        'dns': 'dns',
        'Access': 'access'
    }
    logger.info('Verifying that there are no conflicting tasks\n')
    verify_no_running_device_import_tasks()
    verify_no_running_device_deletion_tasks()
    verify_no_running_agent_install_tasks()
    device_list = retrieve_device_list()
    rediscovered_devices = rediscover_devices(device_list)
    reimport_devices(rediscovered_devices)


if __name__ == "__main__":
    main()
