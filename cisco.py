import subprocess
import time
import csv
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Configuration
ADB_KEY_PATH = r'C:\Users\v-adamarla\.android\adbkey'
ADB_PUB_KEY_PATH = r'C:\Users\v-adamarla\.android\adbkey.pub'
CSV_FILE_PATH = r'D:\Zabbix\Zabbix-Jerkins\Poly,yealink,logi-host.csv'
BASE_URL = "https://{device_ip}/web/"
USERNAME = "admin"
PASSWORD = "Admin@123"
CHECK_INTERVAL = 300  # Time interval in seconds (5 minutes)


def execute_adb_command(command):
    """Execute an ADB command and return the output."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command '{command}': {e.stderr}")
        return None


def get_connected_devices():
    """Retrieve the list of currently connected devices via ADB, ignoring port numbers."""
    print("Checking connected devices...")
    output = execute_adb_command('adb devices -l')
    connected_devices = []

    for line in output.splitlines():
        if "device" in line and not line.startswith("List of devices"):
            # Extract the UDID and remove any port number (e.g., ":5555")
            udid = line.split()[0].split(':')[0]  # Split on ':' and take the first part
            connected_devices.append(udid)  # Add the cleaned UDID to the list

    return connected_devices


def generate_adb_key(key_path):
    """Generate ADB key."""
    keygen_command = f'adb keygen {key_path}'
    print("Generating ADB key...")
    execute_adb_command(keygen_command)

def reconnect_devices(device_ips):
    """Reconnect devices to ensure all from the CSV are connected."""
    print("Reconnecting all devices...")

    # Disconnect all devices
    execute_adb_command('adb disconnect')

    # Reconnect each device
    for device_ip in device_ips:
        print(f"Reconnecting to device: {device_ip}")
        connect_command = f'adb connect {device_ip}'
        execute_adb_command(connect_command)

def read_public_key(pub_key_path):
    """Read the generated public key."""
    print("Reading public key...")
    with open(pub_key_path, 'r') as file:
        return file.read().strip()

def setup_web_driver():
    """Setup Selenium WebDriver."""
    options = webdriver.ChromeOptions()
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--allow-insecure-localhost')
    return webdriver.Chrome(options=options)

def paste_public_key(public_key, driver, device_ip):
    """Paste the public key into the Cisco device via its web interface."""
    device_url = BASE_URL.format(device_ip=device_ip)
    print(f"Navigating to the device page: {device_url}")
    
    try:
        driver.get(device_url)

        # Check if the login page is loaded
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "username"))).send_keys(USERNAME)
        password_field = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "password")))
        password_field.send_keys(PASSWORD)
        password_field.send_keys(Keys.RETURN)
        print("Logged into the device.")

        # Navigate to Developer API
        dev_api_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "//nav//a[contains(text(),'Developer API')]"))
        )
        dev_api_button.click()
        print("Opened Developer API page.")

        # Paste public key
        input_field = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.XPATH, "//textarea")))
        input_field.send_keys(f'xCommand SystemUnit Extension Adb Enable Key: "{public_key}"')
        print("Pasted public key.")

        # Click Apply
        apply_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "/html/body/div/div/div[2]/div/div[2]/div[2]/p[2]/button"))
        )
        apply_button.click()
        print("Clicked Apply button. Public key applied successfully.")

        return True  # Successfully interacted with the web interface.

    except Exception as e:
        print(f"Error accessing the web interface for {device_ip}: {e}")
        return False  # Web interface interaction failed.

def read_device_ips_from_csv(file_path):
    """Read the device IPs (UDID) from a CSV file, filtering for host names starting with 'Cisco'."""
    device_ips = []
    cisco_hosts = 0  # Counter for the number of Cisco hosts

    try:
        with open(file_path, newline='', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            print(f"CSV Headers: {reader.fieldnames}")  # Debugging: Check column names

            for row in reader:
                # Clean up keys and values, remove any empty columns
                cleaned_row = {key.strip(): value.strip() for key, value in row.items() if key and value}

                # Handle possible BOM issue in 'Host' column
                host = cleaned_row.get('Host', '').strip()  # Get the 'Host' column, default to an empty string

                # Debugging: Check what the 'Host' value is
                print(f"Host Value: '{host}'")  # Log the cleaned Host value

                if host.lower().startswith('cisco'):  # Case-insensitive check
                    udid = cleaned_row.get('udid', '').strip()  # Get the 'udid' column
                    if udid:  # Check for valid UDID
                        device_ips.append(udid)
                        cisco_hosts += 1
                    else:
                        print(f"Skipping row with missing IP for Cisco host: {row}")
                else:
                    print(f"Skipping non-Cisco host: {host}")

        print(f"Total number of Cisco hosts: {cisco_hosts}")
    except Exception as e:
        print(f"Error reading CSV file: {e}")

    return device_ips

def monitor_and_reconnect(device_ips):

    """Periodically monitor and reconnect devices."""
    while True:
        connected_devices = get_connected_devices()
        print(f"Currently connected devices: {connected_devices}")

        # Compare the connected devices with the expected device IPs
        if set(connected_devices) != set(device_ips):
            print("Mismatch detected between connected devices and expected devices. Reconnecting...")
            reconnect_devices(device_ips)
        else:
            print("All devices are connected as expected.")

        # Wait before the next check
        time.sleep(CHECK_INTERVAL)

def connect_with_retry(device_ip, retries=3, delay=5):
    """Attempt to connect to a device via ADB with retries."""
    for attempt in range(retries):
        result = execute_adb_command(f'adb connect {device_ip}')
        if "connected" in result or "already connected" in result:
            return True
        print(f"Retrying connection to {device_ip} ({attempt + 1}/{retries})...")
        time.sleep(delay)
    return False

def main():
    """Main execution flow."""
    generate_adb_key(ADB_KEY_PATH)
    public_key = read_public_key(ADB_PUB_KEY_PATH)
    print(f"Public Key:\n{public_key}")

    # Read device IPs from the CSV file
    device_ips = read_device_ips_from_csv(CSV_FILE_PATH)
    print("Device IPs:", device_ips)

    if not device_ips:
        print("No valid device IPs found in the CSV file.")
        return  # Exit script if no device IPs are found

    # Restart ADB server once
    print("Restarting ADB server...")
    execute_adb_command('adb kill-server')
    execute_adb_command('adb start-server')

    # Initialize Selenium WebDriver
    driver = setup_web_driver()
    try:
        for device_ip in device_ips:
            print(f"Processing device at IP: {device_ip}...")

            # Attempt to paste the public key via web interface
            success = paste_public_key(public_key, driver, device_ip)

            if not success:
                print(f"Device {device_ip} might be in Navigator mode. Attempting ADB connection...")
                if connect_with_retry(device_ip):
                    print(f"Device {device_ip} successfully connected in Navigator mode.")
                else:
                    print(f"Failed to connect to device {device_ip} in Navigator mode. Skipping...")
                continue  # Move to the next device

            # Connect to the device via ADB
            connect_command = f'adb connect {device_ip}'
            connection_result = execute_adb_command(connect_command)

            if "AUTH_FAILED" in connection_result:
                print(f"Skipping device {device_ip} due to authentication failure.")
                continue

            print(f"Device {device_ip} connected successfully.")
    finally:
        driver.quit()

    # Start monitoring and reconnecting in the background
    monitor_and_reconnect(device_ips)


if __name__ == "__main__":
    main()
