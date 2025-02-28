# Network Packet Analyzer

A simple packet sniffer tool written in Python that captures and analyzes network packets. This tool displays relevant information such as source and destination IP addresses, protocols, and payload data. It is intended for educational purposes and should be used ethically.

## Features

- Captures network packets from a specified interface.
- Displays source and destination IP addresses.
- Identifies transport layer protocols (TCP/UDP).
- Logs payload data for further analysis.

## Requirements

- Python 3.x
- Scapy library
- Npcap (for Windows users)

## Installation

1. **Install Python**: Make sure you have Python installed on your machine. You can download it from [python.org](https://www.python.org/downloads/).

2. **Install Scapy**: Open your terminal or command prompt and run the following command:
   ```bash
   pip install scapy

3. **Install Npcap (Windows only)**:  
  - Download Npcap from the Npcap website.  
  - Run the installer and ensure to check the option "Install Npcap in WinPcap API-compatible Mode."  

4. Download the Packet Sniffer Script: Copy the packet sniffer code provided in this repository and save it as Network_Packet_Analyzer.py.  

5. Usage
  - Open a terminal or command prompt.  
  - Navigate to the directory where you saved Network_Packet_Analyzer.py.  
  - Run the script using the following command:
       python3 Network_Packet_Analyzer.py

6. Specify the Network Interface:  
Replace "eth0" in the main function with the appropriate network interface for your system (e.g., Wi-Fi for wireless connections).

