# BIG-IQ Device Re-Import and Rediscover Script

This Python script is designed to rediscover and re-import devices on a BIG-IQ system. It ensures that no conflicting tasks are running before proceeding with device operations. The script supports logging for both console output and file output, making it easy to monitor and troubleshoot.

## Features

- **Device Rediscovery**: Re-discovers devices and ensures their configurations are up-to-date.
- **Device Re-Import**: Re-imports device configurations and updates them on BIG-IQ.
- **Conflict Checking**: Verifies that there are no conflicting tasks (e.g., device import, device deletion, agent installation) running before starting the process.
- **Logging**: Logs detailed information and errors both to the console and to a file for easier troubleshooting.

## Prerequisites

- Python 2.7
- BIG-IQ with the necessary permissions to execute device rediscovery and re-import operations.

## Installation

1. **Copy the Script to the BIG-IQ Server**:

   Copy the Python script to the `/shared/scripts/` directory on your BIG-IQ server. This can be done using `scp` or any other file transfer method.

  ```bash 
  scp reconcile.py your_username@your_bigiq:/shared/scripts/
  ```

2. **Install Required Python Packages:**

   Make sure that the required Python packages (requests, urllib3) are installed on your BIG-IQ system. If not, install them using pip.

    ```bash
    pip install -r requirements.txt
    ```

## Usage

To execute the script, you can use the following command:

```bash
python /shared/scripts/reconcile.py --username YOUR_USERNAME --password YOUR_PASSWORD --hostname YOUR_BIGIQ_HOSTNAME --debug
```

Command Line Arguments:

    --username (Required): The BIG-IQ username. Defaults to admin if not provided.
    --password (Required): The password for the BIG-IQ user.
    --hostname (Optional): The hostname or IP address of the BIG-IQ server. Defaults to localhost.
    --target (Optional): Specific BIG-IP devices to re-import. Provide multiple hostnames separated by spaces.
    --targetfile (Optional): Path to a plain text file containing a list of BIG-IP hostnames to re-import. One hostname per line.
    --debug (Optional): Enable debug logging for more detailed output.

### Example:

```bash
python /shared/scripts/reconcile.py --username admin --password my_password --hostname bigiq.example.com --target device1.example.com device2.example.com --debug
```

### Logging

    Console Logging: All operations and debug information are output to the console in real-time.
    File Logging: A detailed log is also maintained at /var/log/reconcile.log on the BIG-IQ server. This log file contains timestamps, log levels, and messages for all script operations, making it easy to review what occurred during the script execution.

Log File Location

The script writes logs to the following file:

```text
/var/log/reconcile.log
```

This file includes all important operations, errors, and debug information.

## Troubleshooting

If the script encounters an error, it will log the error message and exit. Check the log file at /var/log/reconcile.log for more details on what caused the issue.

## Security Considerations

Password Handling: Avoid hardcoding passwords in the script or command line. Consider using environment variables or other secure methods to manage passwords.

File Permissions: Ensure that the script and log files are only accessible to authorized users on the BIG-IQ system.

## Additional Information

For more details on BIG-IQ and device management, refer to the official BIG-IQ documentation.

## License

This script is provided "as is," without any warranties or guarantees. Use it at your own risk.
