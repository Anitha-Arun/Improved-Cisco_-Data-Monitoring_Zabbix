import subprocess
import logging
import csv
import time
import datetime
import os
import glob
import threading
import subprocess
import time
import json
import re
from datetime import datetime, timedelta, timezone

# Constants
CSV_FILE_PATH = r''  # Your CSV file path
ZABBIX_SERVER = ''  # Replace with your Zabbix server
DATA_FOLDER = 'data'  # Folder to store logcat and bugreport files
EXTRACTED_DATA_FOLDER = os.path.join(DATA_FOLDER, 'extracted')
#package
 # Collect memory usage for important packages
packages = {
            "Teams": "com.microsoft.skype.teams.ipphone",
            "Admin Agent": "com.microsoft.teams.ipphone.admin.agent",
            "Company Portal": "com.microsoft.windowsintune.companyportal"
        }

# Setup logging
logging.basicConfig(filename='device_monitor.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create necessary folders
os.makedirs(DATA_FOLDER, exist_ok=True)
os.makedirs(EXTRACTED_DATA_FOLDER, exist_ok=True)

def convert_timestamp_to_ist(timestamp_ms):
    """Convert timestamp in milliseconds to IST string."""
    try:
        timestamp_s = int(timestamp_ms) / 1000.0
        utc_time = datetime.fromtimestamp(timestamp_s, tz=timezone.utc)  # Fixed datetime usage
        ist_time = utc_time + timedelta(hours=5, minutes=30)
        return ist_time.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        return f"Invalid timestamp: {e}"


def parse_agent_repository_line(line, output_file, previous_mac_addresses, last_signin_state):
    """Parse a single AgentRepository log line and write to output file."""
    try:
        json_match = re.search(r'AgentRepository:\s*(\{.*\})', line)
        if not json_match:
            return last_signin_state

        json_data = json.loads(json_match.group(1))
        
        # Write section separator
        output_file.write(f"\n{'='*80}\n")
        
        # Process Cookie Information
        if "cookie" in json_data:
            output_file.write("COOKIE INFORMATION:\n")
            output_file.write("-" * 50 + "\n")
            cookie_data = json.loads(json_data["cookie"])
            for item in cookie_data:
                output_file.write(f"Key: {item['key']}\n")
                output_file.write(f"Value: {item['value']}\n")
                output_file.write(f"Expires At: {item['expiresAt']}\n")
            output_file.write("\n")

        # Process Connection and Device Info
        output_file.write("CONNECTION AND DEVICE INFO:\n")
        output_file.write("-" * 50 + "\n")
        output_file.write(f"Current Connection Mode: {json_data.get('currentConnectionMode', 'N/A')}\n")
        output_file.write(f"Device ID: {json_data.get('deviceId', 'N/A')}\n")
        output_file.write(f"IP Address: {json_data.get('ipAddress', 'N/A')}\n\n")

        # Process MAC Addresses
        if 'macAddresses' in json_data:
            output_file.write("MAC ADDRESSES:\n")
            output_file.write("-" * 50 + "\n")
            for mac in json_data['macAddresses']:
                current_mac = mac['macAddress']
                interface = mac['interfaceType']
                if interface not in previous_mac_addresses:
                    previous_mac_addresses[interface] = []
                if current_mac not in previous_mac_addresses[interface]:
                    output_file.write(f"MAC Address for {interface} changed to: {current_mac}\n")
                    previous_mac_addresses[interface].append(current_mac)
                else:
                    output_file.write(f"{interface}: {current_mac}\n")
            output_file.write("\n")

        # Process Metadata
        if 'metaData' in json_data:
            process_metadata(json_data['metaData'], output_file, last_signin_state)

        # Process Software Versions
        if 'softwareVersions' in json_data:
            output_file.write("SOFTWARE VERSIONS:\n")
            output_file.write("-" * 50 + "\n")
            sw_versions = json_data['softwareVersions']
            for key, value in sw_versions.items():
                if isinstance(value, list):
                    output_file.write(f"{key}:\n")
                    for item in value:
                        output_file.write(f" - {item}\n")
                else:
                    output_file.write(f"{key}: {value}\n")
            output_file.write("\n")

        # Process Teams Identifier
        if 'teamsIdentifier' in json_data:
            output_file.write("TEAMS IDENTIFIER:\n")
            output_file.write("-" * 50 + "\n")
            teams_id = json.loads(json_data['teamsIdentifier'])
            output_file.write(f"Device ID: {teams_id['deviceId']}\n\n")

        output_file.write(f"{'#'*80}\n\n")
        
        # Return the updated signin state
        return get_signin_state(json_data)

    except json.JSONDecodeError as e:
        logging.error(f"JSON parsing error in line: {e}")
        return last_signin_state
    except Exception as e:
        logging.error(f"Error parsing line: {e}")
        return last_signin_state


def process_metadata(metadata, output_file, last_signin_state):
    """Process metadata section of the log."""
    output_file.write("METADATA:\n")
    output_file.write("-" * 50 + "\n")
    output_file.write(f"Flavor: {metadata.get('flavor', 'N/A')}\n\n")

    if 'logOnData' in metadata:
        process_logon_data(metadata['logOnData'], output_file, last_signin_state)

    if 'userInfo' in metadata:
        process_user_info(metadata['userInfo'], output_file)


def process_logon_data(logon_data, output_file, last_signin_state):
    """Process logon data section."""
    output_file.write("LOGON DATA:\n")
    output_file.write("-" * 50 + "\n")

    if 'authenticatedUsers' in logon_data:
        output_file.write("Authenticated Users:\n")
        for user in logon_data['authenticatedUsers']:
            output_file.write(f" Account Type: {user.get('accountType', 'N/A')}\n")
            output_file.write(f" Cloud Type: {user.get('cloudType', 'N/A')}\n")
            output_file.write(f" Login Mode: {user.get('loginMode', 'N/A')}\n")
            output_file.write(f" Usage Mode: {user.get('usageMode', 'N/A')}\n")
            output_file.write(f" User ID: {user.get('userId', 'N/A')}\n\n")

    output_file.write(f"Current Active User ID: {logon_data.get('currentActiveUserId', 'N/A')}\n\n")

    process_device_info(logon_data.get('deviceInfo', {}), output_file)
    process_error_info(logon_data.get('errorInfo', {}), output_file)
    process_sign_in_info(logon_data.get('signInInfo', {}), output_file, last_signin_state)
def process_user_info(user_info, output_file):
    """Process user info section."""
    output_file.write("USER INFO:\n")
    output_file.write("-" * 50 + "\n")
    output_file.write(f"Sign In State: {user_info.get('signInState', 'N/A')}\n")
    raw_timestamp = user_info.get('timestamp', 'N/A')
    converted_timestamp = convert_timestamp_to_ist(raw_timestamp) if raw_timestamp != 'N/A' else 'N/A'
    output_file.write(f"Timestamp (IST): {converted_timestamp}\n")
    output_file.write(f"Usage Mode: {user_info.get('usageMode', 'N/A')}\n\n")

def process_device_info(device_info, output_file):
    """Process device info section."""
    if device_info:
        output_file.write("Device Info:\n")
        output_file.write(f" Can Current User Hotdesk: {device_info.get('canCurrentUserHotdesk', 'N/A')}\n")
        output_file.write(f" Device Category: {device_info.get('deviceCategory', 'N/A')}\n")
        output_file.write(f" Host User ID: {device_info.get('hostUserId', 'N/A')}\n\n")

def process_error_info(error_info, output_file):
    """Process error info section."""
    if error_info:
        output_file.write("Error Info:\n")
        output_file.write(f" Error Code: {error_info.get('errorCode', 'N/A')}\n")
        output_file.write(f" Error Message: {error_info.get('errorMsg', 'N/A')}\n")
        output_file.write(f" Remedy Link: {error_info.get('remedyLink', 'N/A')}\n\n")

def process_sign_in_info(sign_info, output_file, last_signin_state):
    """Process sign in info section."""
    if sign_info:
        output_file.write("Sign In Info:\n")
        sign_in_state = sign_info.get('signInState', 'N/A')
        timestamp = sign_info.get('timestamp', 'N/A')
        converted_timestamp = convert_timestamp_to_ist(timestamp) if timestamp != 'N/A' else 'N/A'
        
        output_file.write(f" Sign In State: {sign_in_state}\n")
        output_file.write(f" Timestamp (IST): {converted_timestamp}\n\n")
        
        # Detect sign-in state change
        if sign_in_state != last_signin_state:
            logging.info(f"Sign In State changed: {last_signin_state} -> {sign_in_state} at {converted_timestamp}")
def get_signin_state(json_data):
    """Extract signin state from JSON data."""
    try:
        if 'metaData' in json_data:
            metadata = json_data['metaData']
            if 'logOnData' in metadata:
                logon_data = metadata['logOnData']
                if 'signInInfo' in logon_data:
                    return logon_data['signInInfo'].get('signInState', 'N/A')
    except Exception:
        pass
    return 'N/A'

def process_logcat_file(logcat_path, hostname):
    """Process a logcat file and extract AgentRepository information."""
    try:
        previous_mac_addresses = {}
        last_signin_state = None
        
        # Create output filename based on the original logcat filename
        base_name = os.path.basename(logcat_path)
        output_filename = f"extracted_{base_name}"
        output_path = os.path.join(EXTRACTED_DATA_FOLDER, output_filename)
        
        with open(logcat_path, 'r', encoding='utf-8') as file, \
             open(output_path, 'w', encoding='utf-8') as output_file:
            
            logging.info(f"Processing logcat file for {hostname}: {logcat_path}")
            output_file.write(f"Logcat Analysis for {hostname}\n")
            output_file.write(f"Generated at: {datetime.now()}\n")  # Fixed datetime usage
            output_file.write(f"{'='*80}\n\n")
            
            for line in file:
                if 'AgentRepository:' in line:
                    last_signin_state = parse_agent_repository_line(
                        line, output_file, previous_mac_addresses, last_signin_state
                    )
            
        logging.info(f"Completed processing logcat file. Extracted data saved to: {output_path}")
        return output_path
    
    except Exception as e:
        logging.error(f"Error processing logcat file {logcat_path}: {e}")
        return None
    
def collect_logcat_for_duration(udid, hostname, duration_seconds):
    """Collect logcat data for specified duration and process it."""
    try:
        start_time = time.time()
        timestamp = datetime.now().isoformat().replace(':', '-')  # Fixed datetime usage
        logcat_filename = os.path.join(DATA_FOLDER, f"logcat_{hostname}_{timestamp}.txt")
        
        logging.info(f"Starting logcat collection for {udid} ({hostname}) for {duration_seconds} seconds.")
        
        with open(logcat_filename, 'w', encoding='utf-8') as log_file:
            process = subprocess.Popen(
                f"adb -s {udid} logcat",
                shell=True,
                stdout=log_file,
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            while time.time() - start_time < duration_seconds:
                time.sleep(1)
            
            process.terminate()
        
        logging.info(f"Logcat collection completed for {udid}. Saved to {logcat_filename}")
        
        # Process the collected logcat file
        extracted_path = process_logcat_file(logcat_filename, hostname)
        if extracted_path:
            logging.info(f"Successfully extracted data from logcat for {hostname} to {extracted_path}")
            # Send the extraction timestamp to Zabbix
            timestamp_minutes = int(time.time() / 60)
            send_to_zabbix(hostname, "logcat.extraction.timestamp", timestamp_minutes)
        
    except Exception as e:
        logging.error(f"Error in logcat collection and processing for {udid}: {e}")


def run_command(command):
    """Run a shell command and return the output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command}' failed with error: {e.stderr.strip()}")
        return None

def get_network_usage(udid):
    """Get network RX and TX bytes from the device, prioritizing Ethernet over WLAN."""
    output = run_command(f"adb -s {udid} shell cat /proc/net/dev")
    if output:
        eth_rx, eth_tx = 0, 0
        wlan_rx, wlan_tx = 0, 0
        
        for line in output.splitlines():
            parts = line.split()
            if "eth0" in line:  # Check for the eth0 interface only
                eth_rx = int(parts[1])  # Received bytes
                eth_tx = int(parts[9])  # Transmitted bytes
            elif "wlan0" in line:  # Check for the wlan0 interface
                wlan_rx = int(parts[1])  # Received bytes
                wlan_tx = int(parts[9])  # Transmitted bytes

        # Prioritize Ethernet over WLAN
        if eth_rx > 0 or eth_tx > 0:
            return eth_rx, eth_tx
        elif wlan_rx > 0 or wlan_tx > 0:
            return wlan_rx, wlan_tx

    logging.warning(f"No network data found for device {udid}")
    return 0, 0  # Default to 0 if nothing found

def get_memory_usage(udid, package_name):
    """Get memory usage for the specified package on the device."""
    output = run_command(f"adb -s {udid} shell dumpsys meminfo {package_name}")
    if output:
        for line in output.splitlines():
            if "TOTAL" in line:
                memory_usage = int(line.split()[1])
                return memory_usage
    logging.warning(f"Memory usage data not found for {package_name} on device {udid}")
    return 0

def get_cpu_usage(udid):
    """Get the current CPU usage for the device."""
    output = run_command(f"adb -s {udid} shell dumpsys cpuinfo")
    if output:
        total_cpu_line = [line for line in output.splitlines() if "TOTAL" in line]
        if total_cpu_line:
            try:
                cpu_usage = float(total_cpu_line[0].split('%')[0].strip())
                return max(cpu_usage, 0.0)  # Ensure no negative CPU usage is returned
            except ValueError as e:
                logging.error(f"Error parsing CPU usage for {udid}: {str(e)}")
                return 0.0
    logging.warning(f"CPU usage data not found for device {udid}")
    return 0.0

def get_battery_health(udid):
    """Get the battery level from the device."""
    output = run_command(f"adb -s {udid} shell dumpsys battery")
    if output:
        for line in output.splitlines():
            if "health" in line:
                get_battery_health = int(line.split(":")[1].strip())
                return get_battery_health
    logging.warning(f"Battery data not found for device {udid}")
    return 0

def get_uptime(udid):
    """Get the network uptime for the device."""
    output = run_command(f"adb -s {udid} shell cat /proc/uptime")
    if output:
        uptime_seconds = float(output.split()[0])
        return uptime_seconds
    logging.warning(f"Uptime data not found for device {udid}")
    return 0.0
def analyze_memory_data(memory_data, hostname, udid):
    """Analyze memory data and check for potential leaks, sending results to Zabbix."""
    print("\n--- Analyzing Memory Data for Potential Leaks ---\n")
    
    for name, mem_usages in memory_data.items():
        print(f"[{name}] Memory Usage Data: {mem_usages} KB")
        
        if len(mem_usages) > 1:
            if mem_usages[-1] > mem_usages[0]:  # Check if there's an increase
                increase_percentage = ((mem_usages[-1] - mem_usages[0]) / mem_usages[0]) * 100
                print(f"Memory usage increased by {increase_percentage:.2f}% over the monitoring period.")
                logging.info(f"Memory usage for {name} increased by {increase_percentage:.2f}%")
                
                zabbix_key = f"memory.leak[{packages[name]}]"  # Zabbix key for memory leak
                send_to_zabbix(hostname, zabbix_key, increase_percentage)  # Send percentage increase
            else:
                print(f"No memory leak detected for {name}. Memory usage is stable or decreased.")
                send_to_zabbix(hostname, f"memory.leak[{packages[name]}]", -1)  # Send -1 or a value to indicate no leak
        else:
            logging.warning(f"Insufficient memory data for {name}, unable to analyze.")
            send_to_zabbix(hostname, f"memory.leak[{packages[name]}]", 0)  # Indicate no analysis could be done


def send_to_zabbix(hostname, key, value):
    """Send data to Zabbix."""
    try:
        command = f'zabbix_sender -z {ZABBIX_SERVER} -s "{hostname}" -k "{key}" -o {value}'
        result = run_command(command)
        if result:
            logging.info(f"Sent to Zabbix: {hostname} - {key} = {value}")
        else:
            logging.error(f"Failed to send data to Zabbix for {hostname}: {key} = {value}")
    except Exception as e:
        logging.error(f"Failed to send data to Zabbix for {hostname}: {str(e)}")

def collect_logcat(udid, hostname):
    """Collect logcat data from the device."""
    output = run_command(f"adb -s {udid} logcat -d")
    if output:
        timestamp = datetime.datetime.now().isoformat().replace(":", "-")  # Replace colons with hyphens
        logcat_filename = os.path.join(DATA_FOLDER, f"logcat_{udid}_{timestamp}.txt")
        
        with open(logcat_filename, 'w', encoding='utf-8') as log_file:
            log_file.write(output)
        logging.info(f"Logcat collected for {udid} and saved to {logcat_filename}")

        # Send logcat collection timestamp to Zabbix
        timestamp_minutes = int(time.time() / 60)  # Convert to minutes since epoch
        send_to_zabbix(hostname, "logcat.collection.timestamp", timestamp_minutes)

        return logcat_filename
    else:
        logging.warning(f"Failed to collect logcat for {udid}")
    return None
def collect_bugreport(udid, hostname):
    """Collect bugreport data from the device."""
    try:
        # Create the data folder if it doesn't exist
        if not os.path.exists(DATA_FOLDER):
            os.makedirs(DATA_FOLDER)
            
        # Run the bugreport command
        command = f"adb -s {udid} bugreport {DATA_FOLDER}"
        subprocess.run(command, shell=True, check=True)
        
        # Get the path of the generated bug report
        list_of_files = glob.glob(os.path.join(DATA_FOLDER, '*'))
        bugreport_path = max(list_of_files, key=os.path.getctime)  # Get the most recent file
        
        # Create the new filename based on the current timestamp
        timestamp = datetime.now().isoformat().replace(":", "-")  # Fixed datetime usage
        new_file_name = f"bugreport_{hostname}_{timestamp}.zip"
        new_file_path = os.path.join(DATA_FOLDER, new_file_name)
        
        # Rename the bug report file
        os.rename(bugreport_path, new_file_path)
        
        logging.info(f"Bugreport collected for {udid} and saved to {new_file_path}")
        
        # Send bugreport collection timestamp to Zabbix
        timestamp_minutes = int(time.time() / 60)  # Convert to minutes since epoch
        send_to_zabbix(hostname, "bugreport.collection.timestamp", timestamp_minutes)
        
        return new_file_path
        
    except Exception as e:
        logging.error(f"Error collecting bugreport for {udid}: {e}")
        return None
    
def send_device_online_status(hostname, is_online):
    """Send device online/offline status to Zabbix."""
    online_status = 1 if is_online else 0
    send_to_zabbix(hostname, "device.online.status", online_status)


def is_device_online(udid):
    """Check if the device is online."""
    if not udid:
        logging.error("UDID is missing, cannot check device status")
        return False

    # Check if the device responds to adb get-state on the default port
    device_status = run_command(f"adb -s {udid} get-state")
    if device_status == "device":
        return True

    # If not, try using the custom port (4242)
    logging.info(f"Device {udid} not responding on default port, trying custom port 4242")
    device_status = run_command(f"adb -s {udid}:4242 get-state")
    if device_status == "device":
        return True

    # Log if the device is offline on both attempts
    logging.info(f"Device {udid} is offline with status: {device_status}")
    return False

def process_device_main(udid, hostname):
    """Process network, memory, CPU, and battery usage for a given device."""
    is_online = is_device_online(udid)
    send_device_online_status(hostname, is_online)  # Send online status first

    if is_online:
        # Send uptime second
        uptime_seconds = get_uptime(udid)
        if uptime_seconds > 0:
            send_to_zabbix(hostname, "device.uptime", uptime_seconds)

        # Proceed with other metrics
        rx_bytes, tx_bytes = get_network_usage(udid)
        if rx_bytes > 0 and tx_bytes > 0:
            send_to_zabbix(hostname, "network.rx.bytes", rx_bytes)
            send_to_zabbix(hostname, "network.tx.bytes", tx_bytes)

        cpu_usage = get_cpu_usage(udid)
        if cpu_usage > 0:
            send_to_zabbix(hostname, "cpu.usage", cpu_usage)

        memory_data = {name: [] for name in packages.keys()}
        check_duration = 5
        check_interval = 60

        for _ in range(check_duration):
            for package_name, package_id in packages.items():
                memory_usage = get_memory_usage(udid, package_id)
                if memory_usage > 0:
                    memory_data[package_name].append(memory_usage)
                    send_to_zabbix(hostname, f"memory.usage[{package_id}]", memory_usage)
            time.sleep(check_interval)

        analyze_memory_data(memory_data, hostname, udid)

        battery_level = get_battery_health(udid)
        if battery_level > 0:
            send_to_zabbix(hostname, "battery.health", battery_level)

def process_device_logs(devices):
    """
    Collect logcat for 5 minutes for all devices, followed by bugreport collection.
    """
    logging.info("Starting logcat collection for all devices.")
    
    # Collect logcat for all devices
    threads = []
    for udid, hostname in devices.items():
        thread = threading.Thread(target=collect_logcat_for_duration, args=(udid, hostname, 300))  # 5 minutes = 300 seconds
        threads.append(thread)
        thread.start()

    # Wait for all logcat threads to complete
    for thread in threads:
        thread.join()
    logging.info("Completed logcat collection for all devices.")

    # Pause before starting bugreport collection
    time.sleep(10)  # Short pause for synchronization (optional)

    logging.info("Starting bugreport collection for all devices.")
    
    # Collect bugreport for all devices sequentially
    for udid, hostname in devices.items():
        collect_bugreport(udid, hostname)  # Bugreport collection doesn't need threading

    logging.info("Completed bugreport collection for all devices.")

    # Wait for 60 seconds before the next cycle
    logging.info("Waiting 60 seconds before starting the next cycle.")
    time.sleep(60)

def main_loop():
    """Main function to read devices from CSV and monitor them."""
    while True:
        try:
            with open(CSV_FILE_PATH, newline='', encoding='utf-8-sig') as csvfile:
                reader = csv.DictReader(csvfile)
                threads = []
                
                for row in reader:
                    if 'Host' in row and 'udid' in row:
                        udid = row['udid'].strip()
                        hostname = row['Host'].strip()
                        
                        if udid and hostname:
                            thread = threading.Thread(
                                target=process_device_main,
                                args=(udid, hostname)
                            )
                            threads.append(thread)
                            thread.start()
                
                for thread in threads:
                    thread.join()
                    
            time.sleep(10)
            
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            time.sleep(30)  # Wait before retrying



def log_collection_loop():
    """Function to collect logs and bugreports in a synchronized manner."""
    while True:
        with open(CSV_FILE_PATH, newline='', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            devices = {row['udid'].strip(): row['Host'].strip() for row in reader if 'Host' in row and 'udid' in row}

        if not devices:
            logging.warning("No devices found in the CSV file. Waiting before retrying.")
            time.sleep(60)
            continue

        # Process all devices for logcat and bugreport collection
        process_device_logs(devices)


if __name__ == "__main__":
    # Start the main monitoring loop in a separate thread
    main_thread = threading.Thread(target=main_loop)
    main_thread.start()

    # Start the log collection loop in the main thread
    log_collection_loop()