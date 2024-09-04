# HTTP Packet Sniffer

This Python script is designed to sniff HTTP traffic on a specified network interface. It captures and analyzes HTTP requests, extracting URLs and potential login credentials (e.g., usernames and passwords) from the sniffed packets.

## Features

- **Capture HTTP Traffic**: The script captures HTTP traffic on the specified network interface.
- **Extract URLs**: It extracts and displays the URLs that the target is visiting.
- **Identify Login Credentials**: The script searches for potential login information such as usernames and passwords within the HTTP requests and highlights them in the output.

## Prerequisites

- **MITM (Man-in-the-Middle)**: You must be positioned as a MITM on the network to capture and inspect HTTP traffic effectively.
- **Scapy Library**: The script uses the Scapy library for packet sniffing and analysis.

  To avoid conflicting dependencies with other Python projects, it is recommended to create a virtual environment (venv):
  
## Setup

1. **Clone the repository:**

    ```bash
    git clone https://github.com/NULLxDEF/packet_sniffer.git
    cd packet_sniffer
    ```

2. **Create and activate the virtual environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install required dependencies:**

    ```bash
    pip install scapy
    ```
  
## Usage

1. **Enable Packet Forwarding**: To ensure that the target's internet connection remains active, enable packet forwarding:

    ```bash
    echo 1 > /proc/sys/net/ipv4/ip_forward
    ```

2. **Run the Script**: Execute the script and specify the network interface you want to sniff on when prompted:

    ```bash
    python3 packet_sniffer.py
    ```

    The script will prompt you to enter the network interface to sniff (e.g., eth0, wlan0).

3. **Monitor the Output**: The script will display the URLs visited by the target and highlight any potential login credentials found in the HTTP requests.

## Important Notes

- **HTTPS Traffic**: This script only captures HTTP traffic. HTTPS traffic cannot be inspected unless downgraded to HTTP.
- **Permissions**: Ensure you have the necessary permissions to perform packet sniffing on the network.
- **Ethical Use**: This script is intended for educational purposes and ethical security testing only. Unauthorized use is prohibited.

## Example Output

When the script is run, the output may look like this:

```plaintext
[+] HTTP Request >>> b'www.example.com/login'
[+] Possible username/password >>> b'user=admin&password=secret'
```



