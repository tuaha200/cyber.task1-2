from netmiko import ConnectHandler
import difflib

# Device connection details
device = {
    'device_type': 'cisco_ios',
    'host': '192.168.56.101',  # Updated IP address
    'username': 'prne',        # Username
    'password': 'cisco123!',   # Password
    'secret': 'cisco12345!',   # Enable secret password
}


hardening_advice = """
service password-encryption
no ip http server
no ip http secure-server
ip ssh version 2
no service telnet
logging buffered
ntp server 192.168.1.100
"""


syslog_server = '192.168.1.100'  


# Task 1


def fetch_running_config(device):
    """Fetch the running config from the device."""
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        running_config = connection.send_command('show running-config')
        return running_config
    except Exception as e:
        print(f"Error connecting to the device: {e}")
        exit(1)

def compare_configurations(running_config, hardening_advice):
    """Compare running configuration with the hardening advice."""
    diff = difflib.unified_diff(
        running_config.splitlines(),
        hardening_advice.splitlines(),
        fromfile='Running Config',
        tofile='Hardening Advice',
    )
    print("\nConfiguration Comparison (Task 1):")
    for line in diff:
        print(line)


# Task 2: 

def enable_syslog_on_device(device, syslog_server):
    """Configure the device to send syslog messages to a syslog server."""
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        config_commands = [
            f'logging {syslog_server}',        # Set syslog server IP
            'logging trap informational',      # Set the logging level (Informational)
            'logging source-interface Vlan1',  
            'logging on'                       # Enable logging
        ]
        connection.send_config_set(config_commands)
        print(f"\nSyslog Configuration Applied: Syslog server {syslog_server}")
    except Exception as e:
        print(f"Error configuring syslog: {e}")
        exit(1)



hardening_checks = {
    "SSH enabled": "ip ssh version 2",
    "Telnet disabled": "no service telnet",
    "Password encryption": "service password-encryption",
    "Logging enabled": "logging buffered",
    "NTP configured": "ntp server"
}

def check_hardening(running_config):
    """Check the device's running config against hardening recommendations."""
    print("\nHardening Checks:")
    for check, rule in hardening_checks.items():
        if rule in running_config:
            print(f"[PASS] {check}")
        else:
            print(f"[FAIL] {check}")



def main():
    # Fetch running configuration
    running_config = fetch_running_config(device)

    # Store the running and startup configurations in text files
    with open('running_config.txt', 'w') as run_file:
        run_file.write(running_config)
    startup_config = connection.send_command('show startup-config')
    with open('startup_config.txt', 'w') as start_file:
        start_file.write(startup_config)

    # Disconnect from the device after saving the configuration
    connection.disconnect()
    print("Configs retrieved and stored successfully.")

    # Task 1: Compare the running config with hardening advice
    compare_configurations(running_config, hardening_advice)

    # Task 2: Enable syslog on the device
    enable_syslog_on_device(device, syslog_server)

    # Task 3: Perform hardening checks
    check_hardening(running_config)

if __name__ == "__main__":
    main()
