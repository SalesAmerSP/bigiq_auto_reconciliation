#!/usr/bin/env python2.7

import requests
import time
import json
import logging
import argparse
import sys
import urllib3

# disable warnings for insecure connections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def setup_logging(debug):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Create a StreamHandler to log to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)

    # Create a formatter and set it for the console handler
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)

    # Add the console handler to the logger
    logger.addHandler(console_handler)

    # Create a FileHandler to log to a file
    file_handler = logging.FileHandler('/var/log/reconcile.log')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def global_token_auth():
    global auth_token
    global auth_token_expiry
    try:
        auth_token
        auth_token_expiry
    except NameError:
        logger.info('The variables auth_token or auth_token_expiry not found; creating variables with dummy values')
        auth_token = 'null'
        auth_token_expiry = 0

    # Check if current epoch time is less than token expiry;
    # skip token generation if not
    if (time.time() < auth_token_expiry):
        remaining_seconds = auth_token_expiry - time.time()
        logger.debug('Existing authentication token is still valid. Expires in {} seconds.'.format(remaining_seconds))
        return

    # request a new token
    url = 'https://{}/mgmt/shared/authn/login'.format(host)
    payload = {'username': username, 'password': password, 'provider': 'tmos'}
    headers = {'Content-type': 'application/json'}
    logger.debug('Token API call: {}, {}, {}'.format(url, headers, username))
    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            verify=False
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error('Error making API call: {}'.format(e))
        sys.exit()

    auth_token = response.json()['token']['token']
    auth_token_expiry = response.json()['token']['exp']
    logger.info('Auth token retrieved with expiration of {} epoch time'.format(auth_token_expiry))


def bigiq_http_get(uri, params):
    global_token_auth()
    url = 'https://{}/{}'.format(host, uri)
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.debug('BIG-IQ HTTP GET URL:{} {}'.format(url, params))
    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            verify=False
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error('Error making API call: {} (Endpoint Response: {})'.format(e, response.text))
        return None
    logger.debug('BIG-IP API Response: {}'.format(response.text))
    return response


def bigiq_http_post(uri, payload):
    global_token_auth()
    url = 'https://{}/{}'.format(host, uri)
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.debug('BIG-IQ HTTP POST {} {}'.format(url, payload))
    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            verify=False
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error('Error making API call: {} (Endpoint Response: {})'.format(e, response.text))
        return None
    logger.debug('BIG-IP API Response: {}'.format(response.text))
    return response


def bigiq_http_patch(uri, payload):
    global_token_auth()
    url = 'https://{}/{}'.format(host, uri)
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.debug('BIG-IQ HTTP PATCH {} {}'.format(url, payload))
    try:
        response = requests.patch(
            url,
            headers=headers,
            json=payload,
            verify=False
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error('Error making API call: {} (Endpoint Response: {})'.format(e, response.text))
        return None
    logger.debug('BIG-IP API Response: {}'.format(response.text))
    return response


def verify_no_running_device_import_tasks():
    # Ensure no conflicting device import tasks sorting by newest Update timestamp
    api_payload = {
        '$orderby': 'lastUpdateMicros desc',
        '$skip': 0,
        '$top': 1
    }
    last_import_task = bigiq_http_get(
        '/mgmt/cm/global/tasks/device-discovery-import-controller',
        api_payload
        )
    try:
        last_import_task.json()['items'][0]['status']
    except (KeyError, IndexError) as e:
        logger.error('Error: {}'.format(e))
        sys.exit(1)
    if last_import_task.json()['items'][0]['status'] == 'RUNNING':
        logger.error('Unexpected running task: {}'.format(last_import_task.text))
        sys.exit()

    # Ensure no conflicting device import tasks sorting by newest Start timestamp
    api_payload = {
        '$orderby': 'startDateTime desc',
        '$skip': 0,
        '$top': 1
    }
    last_import_task = bigiq_http_get(
        '/mgmt/cm/global/tasks/device-discovery-import-controller',
        api_payload
        )
    try:
        last_import_task.json()['items'][0]['status']
    except (KeyError, IndexError) as e:  # Use KeyError and IndexError instead of NameError
        logger.error('Error: {}'.format(e))
        sys.exit(1)
    if last_import_task.json()['items'][0]['status'] == 'RUNNING':
        logger.error('Unexpected running task: {}'.format(last_import_task.text))
        sys.exit()
    else:
        logger.info('No conflicting import tasks found')


def verify_no_running_device_deletion_tasks():
    api_payload = {
        '$orderby': 'lastUpdateMicros desc',
        '$skip': 0,
        '$top': 1
    }
    last_device_deletion_task = bigiq_http_get(
        '/mgmt/cm/global/tasks/device-remove-trust',
        api_payload
    )
    try:
        last_device_deletion_task.json()['items'][0]['status']
    except (KeyError, IndexError) as e:  # Use KeyError and IndexError instead of NameError
        logger.error('Error: {}'.format(e))
        sys.exit(1)
    if last_device_deletion_task.json()['items'][0]['status'] == 'RUNNING':
        logger.error('Unexpected running task: {}'.format(last_device_deletion_task.text))
        sys.exit()
    else:
        logger.info('No conflicting device deletion tasks found')


def verify_no_running_agent_install_tasks():
    # Ensure no active agent install tasks
    api_payload = {
        '$orderby': 'lastUpdateMicros desc',
        '$skip': 0,
        '$top': 1
    }
    last_agent_install_task = bigiq_http_get(
        '/mgmt/cm/shared/stats-mgmt/agent-install-and-config-task',
        api_payload
    )
    try:
        last_agent_install_task.json()['items'][0]['status']
    except (KeyError, IndexError) as e:  # Use KeyError and IndexError instead of NameError
        logger.error('Error: {}'.format(e))
        sys.exit(1)
    if last_agent_install_task.json()['items'][0]['status'] == 'RUNNING':
        logger.error('Running task: {}'.format(last_agent_install_task.text))
        sys.exit()
    else:
        logger.info('No conflicting agent install tasks found')


def retrieve_device_list():
    # Gather a list of all devices and provisioned modules
    api_payload = json.loads('{"multiStageQueryRequest":{"repeatLastStageUntilTerminated":false,"queryParamsList":[{"description":"retrieval","filterProcessorReference":{"link":"https://localhost/mgmt/shared/resolver/device-groups/cm-bigip-allBigIpDevices/devices?%24filter=product%20eq%20\'BIG-IP\'&%24orderby=hostname%20asc%2Caddress%20asc"},"pipelineAction":"DATA_RETRIEVAL","runStageInternally":false},{"description":"pagination","managedPipelineWorkerName":"page-pipe","jsonContext":{"skip":0,"top":5000},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/system/machineid-resolver","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/system/machineid-resolver"},"joinConditions":"machineId=machineId","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"sameDevices"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/global/tasks/device-remove-mgmt-authority?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/global/tasks/device-remove-mgmt-authority?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage"},"joinConditions":"selfLink=deviceReference/link","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"rmaTasks"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/global/tasks/device-remove-trust?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/global/tasks/device-remove-trust?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage"},"joinConditions":"selfLink=deviceReference/link","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"removeTrustTasks"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/shared/stats-mgmt/agent-install-and-config-task?%24orderby=lastUpdateMicros%20desc&%24select=targetDeviceReference%2Cstatus%2CerrorMessage","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/shared/stats-mgmt/agent-install-and-config-task?%24orderby=lastUpdateMicros%20desc&%24select=targetDeviceReference%2Cstatus%2CerrorMessage"},"joinConditions":"selfLink=targetDeviceReference/link","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"agentTasksList"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/shared/stats-mgmt/stats-configuration?%24select=machineId%2Cmodules","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/shared/stats-mgmt/stats-configuration?%24select=machineId%2Cmodules"},"joinConditions":"machineId=machineId","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"statsConfigInfo"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"join_https://localhost/mgmt/cm/shared/current-config/sys/provision?%24select=name%2CdeviceReference&%24filter=level%20ne%20\'none\'","managedPipelineWorkerName":"join-pipe","jsonContext":{"rightQueryReference":{"link":"https://localhost/mgmt/cm/shared/current-config/sys/provision?%24select=name%2CdeviceReference&%24filter=level%20ne%20\'none\'"},"joinConditions":"machineId=deviceReference/machineId","joinType":"LEFT","itemToRetain":"LEFT","joinedItemsToRetainListName":"provisioningInfo"},"pipelineAction":"DATA_PROCESSING","runStageInternally":false},{"description":"stats","managedPipelineWorkerName":"resource-stats-pipe","pipelineAction":"DATA_PROCESSING","runStageInternally":false}]},"getOnPostAndTerminate":true,"isPerformanceBoostingEnabled":false}')
    device_list = bigiq_http_post(
        '/mgmt/shared/pipeline/manager/BIG-IP-Devices-Pipeline',
        api_payload
    )
    device_list = device_list.json()
    device_removal_list = []
    if targets == None:
        logger.info('No targets specified -- will attempt to reimport and rediscover all BIG-IPs')
    else:
        logger.info('Narrowing scope to targets: {}'.format(targets))
        for current_device in device_list['items']:
            logger.info('Checking device {} against target list'.format(current_device['hostname']))
            if current_device['hostname'] not in targets:
                device_removal_list.append(current_device)
        for current_device in device_removal_list:
            device_list['items'].remove(current_device)
            logger.warning('Removing device {} from device list'.format(current_device['hostname']))
    return device_list

def rediscover_devices(device_list):
    rediscovered_devices = []
    # Parse Devices and Re-discover/Re-import
    for current_device in device_list['items']:
        logger.info('Attempting to rediscover {}'.format(current_device['hostname']))
        try:    # check for device trust
            device_modules_provisioned = current_device['sameDevices'][0]['properties']['cm:gui:module']
            logger.info('Reported device modules provisioned: {}'.format(device_modules_provisioned))
        except (KeyError, IndexError) as e:  # Use KeyError and IndexError instead of NameError
            logger.error('Error: {}'.format(e))
            sys.exit(1)
        # Retrieve existing discovery task for reuse
        api_params = {
            '$filter': 'deviceReference/link eq \'*{}\''.format(current_device['machineId'])
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
        # Add the shared security module if the firewall module is present
        if ({'module': 'firewall'} in module_discovery_list) and ({'module': 'security_shared'} not in module_discovery_list):
            logger.warning('{} module list includes firewall but does not include security_shared; appending to module list'.format(current_device['hostname']))
            module_discovery_list.append({'module': 'security_shared'})
        # Add the shared security module if the asm module is present
        if ({'module': 'asm'} in module_discovery_list) and ({'module': 'security_shared'} not in module_discovery_list):
            logger.warning('{} module list includes asm but does not include security_shared; appending to module list'.format(current_device['hostname']))
            module_discovery_list.append({'module': 'security_shared'})
        logger.info('{} has the following modules: {}'.format(current_device['hostname'], module_discovery_list))
        # Check for existing discovery tasks; skip if not discovered before; reuse existing if found
        if existing_discovery_task.json()['totalItems'] == 0:
            logger.warning('{} has never been discovered; skipping'.format(current_device['hostname']))
        elif existing_discovery_task.json()['totalItems'] >= 1:
            existing_discovery_task_id = existing_discovery_task.json()['items'][0]['id']
            existing_discovery_task_api_payload = {
                'moduleList': module_discovery_list,
                'status': 'STARTED'
            }
            reused_discovery_task = bigiq_http_patch(
                'mgmt/cm/global/tasks/device-discovery/{}'.format(existing_discovery_task_id),
                existing_discovery_task_api_payload
            )
            executed_task_id = reused_discovery_task.json()['id']
            executed_task_status_text = reused_discovery_task.json()['status']
        while (executed_task_status_text == 'STARTED'):
            api_params = {}
            executed_task_status = bigiq_http_get(
                'mgmt/cm/global/tasks/device-discovery/{}'.format(executed_task_id),
                api_params
            )
            executed_task_status_text = (
                executed_task_status.json()['status']
            )
        if executed_task_status_text == 'FINISHED':
            logger.info('{} successfully rediscovered!'.format(current_device['hostname']))
            rediscovered_devices.append(current_device)
        else:
            logger.error('Re-discovery did not finish successfully with task status: {}'.format(executed_task_status_text))
            logger.error('Failed task payload {}'.format(executed_task_status.json()))
    return rediscovered_devices


def reimport_devices(device_list):
    for current_device in device_list:
        # Compile a list of modules to discover based on pre-discovered modules
        device_modules_provisioned = current_device['sameDevices'][0]['properties']['cm:gui:module']
        module_import_list = []
        for key, value in bigip_import_module_mapping.items():
            if (key in device_modules_provisioned) and (key != 'Access'):
                module_import_list.append({'module': value})
        for current_module in module_import_list:
            logger.info('Attempting to reimport module {}'.format(current_module['module']))
            api_payload = {
                'createChildTasks': False,
                'skipDiscovery': True,
                'deviceReference': {
                    'link': current_device['selfLink']
                },
                'snapshotWorkingConfig': True,
                'useBigiqSync': False,
                'name': 'reimport_{}_{}'.format(current_module, time.time()),
                'globalConflictResolutionType': 'USE_BIGIP',
                'globalDeviceConflictResolutionType': 'USE_BIGIP',
                'globalVersionedConflictResolutionType': 'USE_BIGIP'
            }
            reimport_task = bigiq_http_post(
                '/mgmt/cm/{}/tasks/declare-mgmt-authority'.format(current_module['module']),
                api_payload
            )
            if (reimport_task.status_code >= 400):
                logger.error('Re-import task for module {} on {} failed!'.format(current_module['module'], current_device))
                logger.error('Failed response from API: {}'.format(reimport_task.text))
            else:
                try:
                    reimport_task_id = reimport_task.json()['id']
                    reimport_task_status_text = reimport_task.json()['status']
                except (KeyError, IndexError) as e:  # Use KeyError and IndexError instead of NameError
                    logger.error('Error: {}'.format(e))
                while reimport_task_status_text == 'STARTED':
                    api_params = {}
                    reimport_task_status = bigiq_http_get(
                        '/mgmt/cm/{}/tasks/declare-mgmt-authority/{}'.format(current_module['module'], reimport_task_id),
                        api_params
                    )
                    reimport_task_status_text = reimport_task_status.json()['status']
                    logger.info('Task status: {}'.format(reimport_task_status_text))
                logger.info('Module {} on {} finished task with status {}'.format(current_module, current_device['hostname'], reimport_task_status_text))


def parse_arguments():
    # Create the parser
    parser = argparse.ArgumentParser(description='Process login credentials and hostname.')

    # Add arguments
    parser.add_argument('--username', type=str, default='admin', help='BIG-IQ username (defaults to admin)')
    parser.add_argument('--password', type=str, required=True, help='password for BIG-IQ')
    parser.add_argument('--hostname', type=str, default='localhost', help='BIG-IQ host (IP/FQDN), defaults to localhost')
    parser.add_argument('--target', type=str, required=False, help='BIG-IP(s) to re-import', nargs='*')
    parser.add_argument('--targetfile', type=argparse.FileType('r'), required=False, help='plain text file with list of target BIG-IP hostnames, one host per line', nargs='?')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    # Parse arguments
    args = parser.parse_args()
    return args


def main():
    # Read command line arguments
    args = parse_arguments()

    # Set up logging
    logger = setup_logging(args.debug)
    global logger

    # Define BIG-IQ environment variables
    global username
    global password
    global host
    global bigip_discovery_module_mapping
    global bigip_import_module_mapping
    global targets

    # Read command line arguments
    username = args.username
    password = args.password
    host = args.hostname
    targets = args.target
    targetfile = args.targetfile
    if targetfile is None:
        logger.warning('No target file specified - skipping')
    else:
        logger.info('Target file specified: {}'.format(targetfile))
        for entry in targetfile:
            if targets is None:
                targets = [entry.replace('\n','')]
            else:
                targets.append(entry.replace('\n',''))
        logger.info('Targets found in target file: {}'.format(targets))

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
    logger.debug('BIG-IP Discovery Module Mapping: {}'.format(bigip_discovery_module_mapping))

    bigip_import_module_mapping = {
        'adc': 'adc-core',
        'networksecurity': 'firewall',
        'sslo': 'sslo',
        'sharedsecurity': 'security-shared',
        'asmsecurity': 'asm',
        'dns': 'dns',
        'fpsfraudprotectionsecurity': 'websafe',
        'Access': 'access',
    }
    logger.info('BIG-IP Import Module Mapping: {}'.format(bigip_import_module_mapping))

    # Verify that there are no conflicting tasks
    logger.info('Verifying that there are no conflicting tasks')
    verify_no_running_device_import_tasks()
    verify_no_running_device_deletion_tasks()
    verify_no_running_agent_install_tasks()
    device_list = retrieve_device_list()

    # Re-discover and re-import devices
    rediscovered_devices = rediscover_devices(device_list)
    reimport_devices(rediscovered_devices)

# Run the main function
if __name__ == '__main__':
    main()
