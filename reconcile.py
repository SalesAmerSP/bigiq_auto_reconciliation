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
    file_handler = logging.FileHandler('reconcile.log')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def global_token_auth(username, password, provider, host):
    """
    Authenticate with the BIG-IQ API and retrieve an auth token.
    """
    global auth_token
    global auth_token_expiry

    try:
        if time.time() < auth_token_expiry:
            remaining_seconds = auth_token_expiry - time.time()
            logger.debug("{} - Existing auth token is valid for {} more seconds.".format(host, remaining_seconds))
            return
    except NameError:
        logger.debug("{} - No existing auth token found; obtaining a new one.".format(host))

    # request a new token
    url = 'https://{}/mgmt/shared/authn/login'.format(host)
    payload = {'username': username, 'password': password, 'provider': 'tmos'}
    headers = {'Content-type': 'application/json'}
    logger.debug('{} - token API call: {}, {}, {}'.format(host, url, headers, username))
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error('{} - Error making API call: {} (Endpoint Response: {})'.format(host, e, response.text))
        sys.exit(1)

    auth_response = response.json()
    auth_token = auth_response['token']['token']
    auth_token_expiry = auth_response['token']['exp']
    logger.debug('{} - Auth token retrieved with expiration of {} epoch time'.format(host, auth_token_expiry))


def bigiq_http_get(host, uri, params):
    """
    Perform an HTTP GET request to the BIG-IQ API.
    """
    global_token_auth(args.username, args.password, args.provider, args.hostname)
    url = 'https://{}/{}'.format(host, uri)
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.debug('BIG-IQ HTTP GET :{} {}'.format(url, params))

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            verify=False
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error('{} - error making API call: {} (Endpoint Response: {})'.format(host, e, response.text))
        return None

    logger.debug('{} - BIG-IP API Response: {}'.format(host, response.text))
    return response


def bigiq_http_post(host, uri, payload):
    """
    Perform an HTTP POST request to the BIG-IQ API.
    """
    global_token_auth(args.username, args.password, args.provider, args.hostname)
    url = 'https://{}/{}'.format(host, uri)
    headers = {'Content-type': 'application/json','X-F5-Auth-Token': auth_token}
    logger.debug('BIG-IQ HTTP POST {} {}'.format(url, payload))
    
    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error('{} - error making API call: {} (Endpoint Response: {})'.format(host, e, response.text))
        return response
    logger.debug('{} - BIG-IP API Response: {}'.format(host, response.text))
    return response


def bigiq_http_patch(host, uri, payload):
    """
    Perform an HTTP PATCH request to the BIG-IQ API.
    """
    global_token_auth(args.username, args.password, args.provider, args.hostname)
    url = 'https://{}/{}'.format(host, uri)
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.debug('BIG-IQ HTTP PATCH {} {}'.format(host, url, payload))
    try:
        response = requests.patch(
            url,
            headers=headers,
            json=payload,
            verify=False
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error('{} - error making API call: {} (Endpoint Response: {})'.format(host, e, response.text))
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
        args.hostname,
        '/mgmt/cm/global/tasks/device-discovery-import-controller',
        api_payload
        )
    try:
        task_count = last_import_task.json()['totalItems']
    except (KeyError, IndexError) as e:
        logger.error('{} - {}'.format(args.hostname, e))
        sys.exit(1)
    if task_count >= 1:        
        try:
            last_import_task.json()['items'][0]['status']
        except (KeyError, IndexError) as e:  # Use KeyError and IndexError instead of NameError
            logger.error('{} - {}'.format(args.hostname, e))
            sys.exit(1)
        if last_import_task.json()['items'][0]['status'] == 'RUNNING':
            logger.error('{} - unexpected running task: {}'.format(args.hostname,last_import_task.text))
            sys.exit()
    else:
        logger.info('{} - No conflicting import tasks found'.format(args.hostname))

    # Ensure no conflicting device import tasks sorting by newest Start timestamp
    api_payload = {
        '$orderby': 'startDateTime desc',
        '$skip': 0,
        '$top': 1
    }
    last_import_task = bigiq_http_get(
        args.hostname,
        '/mgmt/cm/global/tasks/device-discovery-import-controller',
        api_payload
        )
    try:
        task_count = last_import_task.json()['totalItems']
    except (KeyError, IndexError) as e:
        logger.error('{} - {}'.format(args.hostname, e))
        sys.exit(1)
    if task_count >= 1:        
        try:
            last_import_task.json()['items'][0]['status']
        except (KeyError, IndexError) as e:  # Use KeyError and IndexError instead of NameError
            logger.error('{} - {}'.format(args.hostname, e))
            sys.exit(1)
        if last_import_task.json()['items'][0]['status'] == 'RUNNING':
            logger.error('{} - unexpected running task: {}'.format(args.hostname, last_import_task.text))
            sys.exit()
    else:
        logger.info('{} - no conflicting import tasks found'.format(args.hostname))


def verify_no_running_device_deletion_tasks():
    api_payload = {
        '$orderby': 'lastUpdateMicros desc',
        '$skip': 0,
        '$top': 1
    }
    last_device_deletion_task = bigiq_http_get(
        args.hostname,
        '/mgmt/cm/global/tasks/device-remove-trust',
        api_payload
    )
    try:
        task_count = last_device_deletion_task.json()['totalItems']
    except (KeyError, IndexError) as e:
        logger.error('{} - {}'.format(args.hostname, e))
        sys.exit(1)
    if task_count >= 1:        
        try:
            last_device_deletion_task.json()['items'][0]['status']
        except (KeyError, IndexError) as e:  # Use KeyError and IndexError instead of NameError
            logger.error('{} - {}'.format(args.hostname, e))
            sys.exit(1)
        if last_device_deletion_task.json()['items'][0]['status'] == 'RUNNING':
            logger.error('{} - unexpected running task: {}'.format(args.hostname, last_device_deletion_task.text))
            sys.exit()
    else:
        logger.info('{} - no conflicting device deletion tasks found'.format(args.hostname))

def verify_no_running_agent_install_tasks():
    # Ensure no active agent install tasks
    api_payload = {
        '$orderby': 'lastUpdateMicros desc',
        '$skip': 0,
        '$top': 1
    }
    last_agent_install_task = bigiq_http_get(
        args.hostname,
        '/mgmt/cm/shared/stats-mgmt/agent-install-and-config-task',
        api_payload
    )
    try:
        task_count = last_agent_install_task.json()['totalItems']
    except Exception as e:
        logger.error('{} - {}'.format(args.hostname, e))
        sys.exit(1)
    if task_count >= 1:        
        try:
            last_agent_install_task.json()['items'][0]['status']
        except Exception as e:
            logger.error('{} - {}'.format(args.hostname - e))
            sys.exit(1)
        if last_agent_install_task.json()['items'][0]['status'] == 'RUNNING':
            logger.error('{} - unexpected running task: {}'.format(args.hostname, last_import_task.text))
            sys.exit()
    else:
        logger.info('{} - no conflicting agent install tasks found'.format(args.hostname))


def retrieve_device_list(targets=None):
    # Gather a list of all devices and provisioned modules
    api_payload = {
        "multiStageQueryRequest": {
            "repeatLastStageUntilTerminated": False,
            "queryParamsList": [
                {
                    "description": "retrieval",
                    "filterProcessorReference": {
                        "link": "https://localhost/mgmt/shared/resolver/device-groups/cm-bigip-allBigIpDevices/devices?%24filter=product%20eq%20'BIG-IP'&%24orderby=hostname%20asc%2Caddress%20asc"
                    },
                    "pipelineAction": "DATA_RETRIEVAL",
                    "runStageInternally": False
                },
                {
                    "description": "pagination",
                    "managedPipelineWorkerName": "page-pipe",
                    "jsonContext": {
                        "skip": 0,
                        "top": 5000
                    },
                    "pipelineAction": "DATA_PROCESSING",
                    "runStageInternally": False
                },
                {
                    "description": "join_https://localhost/mgmt/cm/system/machineid-resolver",
                    "managedPipelineWorkerName": "join-pipe",
                    "jsonContext": {
                        "rightQueryReference": {
                            "link": "https://localhost/mgmt/cm/system/machineid-resolver"
                        },
                        "joinConditions": "machineId=machineId",
                        "joinType": "LEFT",
                        "itemToRetain": "LEFT",
                        "joinedItemsToRetainListName": "sameDevices"
                    },
                    "pipelineAction": "DATA_PROCESSING",
                    "runStageInternally": False
                },
                {
                    "description": "join_https://localhost/mgmt/cm/global/tasks/device-remove-mgmt-authority?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage",
                    "managedPipelineWorkerName": "join-pipe",
                    "jsonContext": {
                        "rightQueryReference": {
                            "link": "https://localhost/mgmt/cm/global/tasks/device-remove-mgmt-authority?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage"
                        },
                        "joinConditions": "selfLink=deviceReference/link",
                        "joinType": "LEFT",
                        "itemToRetain": "LEFT",
                        "joinedItemsToRetainListName": "rmaTasks"
                    },
                    "pipelineAction": "DATA_PROCESSING",
                    "runStageInternally": False
                },
                {
                    "description": "join_https://localhost/mgmt/cm/global/tasks/device-remove-trust?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage",
                    "managedPipelineWorkerName": "join-pipe",
                    "jsonContext": {
                        "rightQueryReference": {
                            "link": "https://localhost/mgmt/cm/global/tasks/device-remove-trust?%24orderby=lastUpdateMicros%20desc&%24select=deviceReference%2Cstatus%2CerrorMessage"
                        },
                        "joinConditions": "selfLink=deviceReference/link",
                        "joinType": "LEFT",
                        "itemToRetain": "LEFT",
                        "joinedItemsToRetainListName": "removeTrustTasks"
                    },
                    "pipelineAction": "DATA_PROCESSING",
                    "runStageInternally": False
                },
                {
                    "description": "join_https://localhost/mgmt/cm/shared/stats-mgmt/agent-install-and-config-task?%24orderby=lastUpdateMicros%20desc&%24select=targetDeviceReference%2Cstatus%2CerrorMessage",
                    "managedPipelineWorkerName": "join-pipe",
                    "jsonContext": {
                        "rightQueryReference": {
                            "link": "https://localhost/mgmt/cm/shared/stats-mgmt/agent-install-and-config-task?%24orderby=lastUpdateMicros%20desc&%24select=targetDeviceReference%2Cstatus%2CerrorMessage"
                        },
                        "joinConditions": "selfLink=targetDeviceReference/link",
                        "joinType": "LEFT",
                        "itemToRetain": "LEFT",
                        "joinedItemsToRetainListName": "agentTasksList"
                    },
                    "pipelineAction": "DATA_PROCESSING",
                    "runStageInternally": False
                },
                {
                    "description": "join_https://localhost/mgmt/cm/shared/stats-mgmt/stats-configuration?%24select=machineId%2Cmodules",
                    "managedPipelineWorkerName": "join-pipe",
                    "jsonContext": {
                        "rightQueryReference": {
                            "link": "https://localhost/mgmt/cm/shared/stats-mgmt/stats-configuration?%24select=machineId%2Cmodules"
                        },
                        "joinConditions": "machineId=machineId",
                        "joinType": "LEFT",
                        "itemToRetain": "LEFT",
                        "joinedItemsToRetainListName": "statsConfigInfo"
                    },
                    "pipelineAction": "DATA_PROCESSING",
                    "runStageInternally": False
                },
                {
                    "description": "join_https://localhost/mgmt/cm/shared/current-config/sys/provision?%24select=name%2CdeviceReference&%24filter=level%20ne%20'none'",
                    "managedPipelineWorkerName": "join-pipe",
                    "jsonContext": {
                        "rightQueryReference": {
                            "link": "https://localhost/mgmt/cm/shared/current-config/sys/provision?%24select=name%2CdeviceReference&%24filter=level%20ne%20'none'"
                        },
                        "joinConditions": "machineId=deviceReference/machineId",
                        "joinType": "LEFT",
                        "itemToRetain": "LEFT",
                        "joinedItemsToRetainListName": "provisioningInfo"
                    },
                    "pipelineAction": "DATA_PROCESSING",
                    "runStageInternally": False
                },
                {
                    "description": "stats",
                    "managedPipelineWorkerName": "resource-stats-pipe",
                    "pipelineAction": "DATA_PROCESSING",
                    "runStageInternally": False
                }
            ]
        },
        "getOnPostAndTerminate": True,
        "isPerformanceBoostingEnabled": False
    }
    device_list = bigiq_http_post(
        args.hostname,
        '/mgmt/shared/pipeline/manager/BIG-IP-Devices-Pipeline',
        api_payload
    )
    device_list = device_list.json()
    device_removal_list = []
    if targets is None:
        logger.info('No targets specified -- will attempt to reimport and rediscover all BIG-IPs')
    else:
        logger.info('Narrowing scope to targets: {}'.format(targets))
        device_list['items'] = [device for device in device_list['items'] if device['hostname'] in targets]
    return device_list['items']

def rediscover_and_reimport_devices(device_list):
    # Parse Devices and Re-discover/Re-import
    for current_device in device_list:
        # Check if device is available
        if current_device['stats']['entries']['health.summary.available']['value'] == 1:
            logger.info('{} - starting rediscovery'.format(current_device['hostname']))
        else:
            logger.warning('{} - device is not available; skipping'.format(current_device['hostname']))
            continue
        # Check if device has provisioned modules
        try:
            provisioning_info = current_device['provisioningInfo']
        except Exception as e:  # Use KeyError and IndexError instead of NameError
            logger.error('{} - {}'.format(current_device['hostname'], e))
            sys.exit(1)
        # Compile a list of modules to discover based on pre-discovered modules
        device_modules_provisioned = []
        # Check for provisioned modules and if they have been previously discovered
        for provisioned_module in provisioning_info:
            logger.debug('{} - verifying reported provisioned module: {}'.format(current_device['hostname'], provisioned_module['name']))
            # Check if the provisioned module is in the list of known modules
            if provisioned_module['name'] == 'ltm':
                logger.debug('{} - LTM module in provisioned list'.format(current_device['hostname']))
                try:
                    if current_device['sameDevices'][0]['properties']['cm-adccore-allbigipDevices']['discovered']:
                        logger.debug('{} - LTM module has been previously discovered'.format(current_device['hostname']))
                        device_modules_provisioned.append({'module': 'adc_core'})
                except KeyError as e:
                    logger.warning('{} - LTM module has not been previously discovered: {}, skipping discovery of this module'.format(current_device['hostname'],e))
            elif provisioned_module['name'] ==  'afm':
                logger.debug('{} - AFM module in provisioned list'.format(current_device['hostname']))
                try:
                    if current_device['sameDevices'][0]['properties']['cm-firewall-allFirewallDevices']['discovered']:
                        logger.debug('{} - AFM module has been previously discovered'.format(current_device['hostname']))
                        device_modules_provisioned.append({'module': 'firewall'})
                        if current_device['sameDevices'][0]['properties']['cm-security-shared-allSharedDevices']['discovered'] and {'module': 'security_shared'} not in device_modules_provisioned:
                            logger.debug('{} - Shared Security module has been previously discovered'.format(current_device['hostname']))
                            device_modules_provisioned.append({'module':'security_shared'})
                except KeyError as e:
                    logger.warning('{} - AFM module has not been previously discovered: {}, skipping discovery of this module'.format(current_device['hostname'], e))
            elif provisioned_module['name'] ==  'apm':
                logger.debug('{} - APM module in provisioned list'.format(current_device['hostname']))
                try:
                    if current_device['sameDevices'][0]['properties']['cm-access-allBigIpDevices']['discovered']:
                        logger.debug('{} - APM module has been previously discovered'.format(current_device['hostname']))
                        device_modules_provisioned.append({'module': 'access'})
                except KeyError as e:
                    logger.warning('{} - APM module has not been previously discovered: {}, skipping discovery of this module'.format(current_device['hostname'], e))
            elif provisioned_module['name'] ==  'fps':
                logger.debug('{} - Fraud Protection Service (FPS) module in provisioned list'.format(current_device['hostname']))
                try:
                    if current_device['sameDevices'][0]['properties']['cm-fps-allBigIpDevices']['discovered']:
                        logger.debug('{} - FPS module has been previously discovered'.format(current_device['hostname']))
                        device_modules_provisioned.append({'module': 'fps'})
                except KeyError as e:
                    logger.warning('{} - FPS module has not been previously discovered: {}, skipping discovery of this module'.format(current_device['hostname'], e))
            elif provisioned_module['name'] ==  'gtm':
                logger.debug('{} - GTM module in provisioned list'.format(current_device['hostname']))
                try:
                    if current_device['sameDevices'][0]['properties']['cm-dns-allBigIpDevices']['discovered']:
                        logger.debug('{} - GTM module has been previously discovered'.format(current_device['hostname']))
                        device_modules_provisioned.append({'module': 'dns'})
                except KeyError as e:
                    logger.warning('{} - GTM module has not been previously discovered: {}, skipping discovery of this module'.format(current_device['hostname'], e))
            elif provisioned_module['name'] ==  'sslo':
                logger.debug('{} - SSLO module in provisioned list')
                try:
                    if current_device['sameDevices'][0]['properties']['cm-sslo-allBigIpDevices']['discovered']:
                        logger.debug('{} - SSLO module has been previously discovered'.format(current_device['hostname']))
                        device_modules_provisioned.append({'module': 'sslo'})
                except KeyError as e:
                    logger.warning('{} - SSLO module has not been previously discovered: {}, skipping discovery of this module'.format(current_device['hostname'],e ))
            elif provisioned_module['name'] ==  'asm':
                logger.debug('{} - ASM module in provisioned list'.format(current_device['hostname']))
                try:
                    if current_device['sameDevices'][0]['properties']['cm-asm-allAsmDevices']['discovered']:
                        logger.debug('{} - ASM module has been previously discovered'.format(current_device['hostname']))
                        device_modules_provisioned.append({'module': 'asm'})
                        if current_device['sameDevices'][0]['properties']['cm-security-shared-allSharedDevices']['discovered'] and {'module': 'security_shared'} not in device_modules_provisioned:
                            logger.debug('{} - Shared Security module has been previously discovered'.format(current_device['hostname']))
                            device_modules_provisioned.append({'module':'security_shared'})
                except KeyError as e:
                    logger.warning('{} - ASM module has not been previously discovered: {}, skipping discovery of this module'.format(current_device['hostname'],e ))
        logger.info('{} - final module discovery list: {}'.format(current_device['hostname'],device_modules_provisioned))
        # Retrieve existing discovery task for reuse
        api_params = {
            '$filter': 'deviceReference/link eq \'*{}\''.format(current_device['machineId'])
        }
        existing_discovery_task = bigiq_http_get(
            args.hostname,
            '/mgmt/cm/global/tasks/device-discovery',
            api_params
        )
        # Check for existing discovery tasks; skip if not discovered before; reuse existing if found
        if existing_discovery_task.json()['totalItems'] == 0:
            logger.warning('{} - no reusable discovery tasks; skipping'.format(current_device['hostname']))
        elif existing_discovery_task.json()['totalItems'] >= 1:
            logger.info('{} - reusing existing discovery task'.format(current_device['hostname']))
            existing_discovery_task_id = existing_discovery_task.json()['items'][0]['id']
            existing_discovery_task_api_payload = {
                'moduleList': device_modules_provisioned,
                'status': 'STARTED'
            }
            reused_discovery_task = bigiq_http_patch(
                args.hostname,
                'mgmt/cm/global/tasks/device-discovery/{}'.format(existing_discovery_task_id),
                existing_discovery_task_api_payload
            )
            executed_task_id = reused_discovery_task.json()['id']
            executed_task_status_text = reused_discovery_task.json()['status']
        while (executed_task_status_text == 'STARTED'):
            api_params = {}
            executed_task_status = bigiq_http_get(
                args.hostname,
                'mgmt/cm/global/tasks/device-discovery/{}'.format(executed_task_id),
                api_params
            )
            executed_task_status_text = (
                executed_task_status.json()['status']
            )
        if executed_task_status_text == 'FINISHED':
            logger.info('{} - rediscovery SUCCESSFUL!'.format(current_device['hostname']))
        else:
            logger.error('{} - rediscovery did not finish successfully with task status: {}. Failed task payload {}'.format(current_device['hostname'], executed_task_status_text,executed_task_status.json()))
        for rediscovered_module in executed_task_status.json()['moduleList']:
            module_name = rediscovered_module['module']
            module_status = rediscovered_module['status']
            if module_status != 'FINISHED':
                logger.error('{} - module {} failed to re-import with status {}'.format(current_device['hostname'], module_name, module_status))
                continue
            else:
                logger.info('{} - attempting to reimport module {}'.format(current_device['hostname'], module_name))
                if module_name == 'adc_core':
                    reimport_module = 'adc-core'
                    api_payload = {
                        'createChildTasks': False,
                        'skipDiscovery': True,
                        'deviceReference': {
                            'link': current_device['selfLink']
                        },
                        'snapshotWorkingConfig': True,
                        'useBigiqSync': False,
                        'name': 'reimport_{}_{}'.format(reimport_module, time.time()),
                        'globalConflictResolutionType': args.globalconflictresolutiontype,
                        'globalDeviceConflictResolutionType': args.globaldeviceconflictresolutiontype,
                        'globalVersionedConflictResolutionType': args.globalversionedconflictresolutiontype
                    }                        
                elif module_name ==  'firewall':
                    reimport_module = 'firewall'
                    api_payload = {
                        'createChildTasks': False,
                        'skipDiscovery': True,
                        'deviceReference': {
                            'link': current_device['selfLink']
                        },
                        'snapshotWorkingConfig': True,
                        'useBigiqSync': False,
                        'name': 'reimport_{}_{}'.format(reimport_module, time.time()),
                        'globalConflictResolutionType': args.globalconflictresolutiontype,
                        'globalDeviceConflictResolutionType': args.globaldeviceconflictresolutiontype,
                        'globalVersionedConflictResolutionType': args.globalversionedconflictresolutiontype
                    }
                elif module_name ==  'sslo':
                    reimport_module = 'sslo'
                    api_payload = {
                        'createChildTasks': False,
                        'skipDiscovery': True,
                        'deviceReference': {
                            'link': current_device['selfLink']
                        },
                        'snapshotWorkingConfig': True,
                        'useBigiqSync': False,
                        'name': 'reimport_{}_{}'.format(reimport_module, time.time()),
                        'globalConflictResolutionType': args.globalconflictresolutiontype,
                        'globalDeviceConflictResolutionType': args.globaldeviceconflictresolutiontype,
                        'globalVersionedConflictResolutionType': args.globalversionedconflictresolutiontype
                    }
                elif module_name ==  'security_shared':
                    reimport_module = 'security-shared'
                    api_payload = {
                        'createChildTasks': False,
                        'skipDiscovery': True,
                        'deviceReference': {
                            'link': current_device['selfLink']
                        },
                        'snapshotWorkingConfig': True,
                        'useBigiqSync': False,
                        'name': 'reimport_{}_{}'.format(reimport_module, time.time()),
                        'globalConflictResolutionType': args.globalconflictresolutiontype,
                        'globalDeviceConflictResolutionType': args.globaldeviceconflictresolutiontype,
                        'globalVersionedConflictResolutionType': args.globalversionedconflictresolutiontype
                    }
                elif module_name ==  'asm':
                    reimport_module = 'asm'
                    api_payload = {
                        'createChildTasks': False,
                        'skipDiscovery': True,
                        'deviceReference': {
                            'link': current_device['selfLink']
                        },
                        'snapshotWorkingConfig': True,
                        'useBigiqSync': False,
                        'name': 'reimport_{}_{}'.format(reimport_module, time.time()),
                        'globalConflictResolutionType': args.globalconflictresolutiontype,
                        'globalDeviceConflictResolutionType': args.globaldeviceconflictresolutiontype,
                        'globalVersionedConflictResolutionType': args.globalversionedconflictresolutiontype
                    }
                elif module_name ==  'dns':
                    reimport_module = 'dns'
                    api_payload = {
                        'createChildTasks': False,
                        'skipDiscovery': True,
                        'deviceReference': {
                            'link': current_device['selfLink']
                        },
                        'snapshotWorkingConfig': True,
                        'useBigiqSync': False,
                        'name': 'reimport_{}_{}'.format(reimport_module, time.time()),
                        'globalConflictResolutionType': args.globalconflictresolutiontype,
                        'globalDeviceConflictResolutionType': args.globaldeviceconflictresolutiontype,
                        'globalVersionedConflictResolutionType': args.globalversionedconflictresolutiontype
                    }
                elif module_name ==  'fps':
                    reimport_module = 'fpsfraudprotectionsecurity'
                    api_payload = {
                        'createChildTasks': False,
                        'skipDiscovery': True,
                        'deviceReference': {
                            'link': current_device['selfLink']
                        },
                        'snapshotWorkingConfig': True,
                        'useBigiqSync': False,
                        'name': 'reimport_{}_{}'.format(reimport_module, time.time()),
                        'globalConflictResolutionType': args.globalconflictresolutiontype,
                        'globalDeviceConflictResolutionType': args.globaldeviceconflictresolutiontype,
                        'globalVersionedConflictResolutionType': args.globalversionedconflictresolutiontype
                    }                        
                elif module_name ==  'access':
                    reimport_module = 'access'
                    logger.debug('{} - Overwriting default API payload with APM import payload using access-group-name {} and cluster name {}'.format(current_device['hostname'], current_device['sameDevices'][0]['properties']['cm-access-allBigIpDevices']['cm:access:access-group-name'], current_device['sameDevices'][0]['properties']['cm-access-allBigIpDevices']['clusterName']))
                    api_payload = {
                        'createChildTasks': False,
                        'skipDiscovery': True,
                        'deviceReference': {
                            'link': current_device['selfLink']
                        },
                        'snapshotWorkingConfig': False,
                        'useBigiqSync': False,
                        'name': 'reimport_{}_{}'.format(reimport_module, time.time()),
                        'properties': {
                            'cm:access:access-group-name': current_device['sameDevices'][0]['properties']['cm-access-allBigIpDevices']['cm:access:access-group-name'],
                            'cm:access:import-shared': True
                        },
                        'clusterName': current_device['sameDevices'][0]['properties']['cm-access-allBigIpDevices']['clusterName']
                    }            
                else:
                    logger.error('{} - module {} not recognized; skipping'.format(current_device['hostname'], module_name))
                    continue                  
            logger.info('{} - re-importing module {}'.format(current_device['hostname'], reimport_module))
            reimport_task = bigiq_http_post(
                args.hostname,
                '/mgmt/cm/{}/tasks/declare-mgmt-authority'.format(reimport_module),
                api_payload
            )
            if reimport_task.status_code >= 400:
                logger.error('{} - Re-import task for module {} failed! Failed response from API: {}'.format(current_device['hostname'], reimport_module, reimport_task.text))
            else:
                try:
                    reimport_task_id = reimport_task.json()['id']
                    reimport_task_status_text = reimport_task.json()['status']
                except Exception as e:
                    logger.error('{} - {}'.format(e))
                while reimport_task_status_text == 'STARTED':
                    api_params = {}
                    reimport_task_status = bigiq_http_get(
                        args.hostname,
                        '/mgmt/cm/{}/tasks/declare-mgmt-authority/{}'.format(reimport_module, reimport_task_id),
                        api_params
                    )
                    reimport_task_status_text = reimport_task_status.json()['status']
                    logger.debug('{} - Task status: {}'.format(current_device['hostname'], reimport_task_status_text))
                logger.info('{} - module {} finished task with status {}'.format(current_device['hostname'], reimport_module, reimport_task_status_text))


def parse_arguments():
    # Create the parser
    parser = argparse.ArgumentParser(description='Process login credentials and hostname.')

    # Add arguments
    parser.add_argument('--username', type=str, default='admin', help='BIG-IQ username (defaults to admin)')
    parser.add_argument('--password', type=str, required=True, help='password for BIG-IQ')
    parser.add_argument('--provider', type=str, default='tmos', help='BIG-IQ authentication provider (defaults to tmos)')
    parser.add_argument('--hostname', type=str, default='localhost', help='BIG-IQ host (IP/FQDN), defaults to localhost')
    parser.add_argument('--target', type=str, required=False, help='BIG-IP(s) to re-import', nargs='*')
    parser.add_argument('--targetfile', type=argparse.FileType('r'), required=False, help='plain text file with list of target BIG-IP hostnames, one host per line', nargs='?')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--globalconflictresolutiontype', type=str, default='USE_BIGIP', help='Conflict resolution type for global settings')
    parser.add_argument('--globaldeviceconflictresolutiontype', type=str, default='USE_BIGIP', help='Conflict resolution type for device settings')
    parser.add_argument('--globalversionedconflictresolutiontype', type=str, default='USE_BIGIP', help='Conflict resolution type for versioned settings')
    
    # Parse arguments
    args = parser.parse_args()
    return args


# Run the main function
if __name__ == '__main__':
    # Read command line arguments
    global args
    args = parse_arguments()

    # Set up logging
    global logger
    logger = setup_logging(args.debug)

    # Check for a list of targets from the command line
    if args.target is None and args.targetfile is None:
        logger.info('No targets specified')
    if args.target:
        logger.info('Targets specified via command line: {}'.format(args.target))
        targets = args.target

    # Check for target list and/or file
    if args.targetfile is not None:
        file_targets = args.targetfile.read().splitlines()
        logger.info('Targets specified in file: {}'.format(targets))
        if targets:
            targets.extend(file_targets)
        else:
            targets = file_targets

    # Verify that there are no conflicting tasks
    logger.debug('Verifying that there are no conflicting device import tasks')
    verify_no_running_device_import_tasks()
    logger.debug('Verifying that there are no conflicting device deletion tasks')
    verify_no_running_device_deletion_tasks()
    logger.debug('Verifying that there are no conflicting agent installation tasks')
    verify_no_running_agent_install_tasks()

    # Retrieve the device list
    device_list = retrieve_device_list()

    # Re-discover devices
    rediscover_and_reimport_devices(device_list)

# End of file
