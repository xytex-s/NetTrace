# Network Packet Sniffer - GUI Usage Guide

## Overview

The GUI application (`sniffer_gui.py`) provides a modern Windows-style interface for the network packet sniffer, making it easy to capture and analyze network traffic without using command-line arguments.

## Features

- **Intuitive Interface**: Clean, organized layout with all controls easily accessible
- **Real-time Packet Display**: See captured packets in a table format with timestamps
- **Live Statistics**: Monitor packet counts by protocol type
- **Advanced Filtering**: Filter by protocol, port, or IP address
- **PCAP Export**: Save captured packets to PCAP files for later analysis
- **Auto-scrolling**: Automatically scrolls to show latest packets

## Requirements

- Python 3.6+
- Administrator/root privileges (required for raw socket access)
- Required packages: `psutil` (install via `pip install psutil`)

## Running the GUI

### Windows

1. Open PowerShell or Command Prompt **as Administrator**
2. Navigate to the project directory
3. Run:
   ```powershell
   python sniffer_gui.py
   ```

### Linux/macOS

1. Open terminal
2. Navigate to the project directory
3. Run:
   ```bash
   sudo python3 sniffer_gui.py
   ```

## Using the Interface

### 1. Select Network Interface

- Choose your network interface from the dropdown menu
- The interface list shows both the interface name and its IP address

### 2. Configure Filters (Optional)

**Protocol Filter:**
- Select "All" to capture all protocols
- Select "TCP", "UDP", or "ICMP" to filter by specific protocol

**Port Filter:**
- Enter a port number (1-65535) to filter packets
- Leave empty to capture all ports

**IP Address Filter:**
- Enter an IP address (e.g., `192.168.1.100`) to filter packets
- Leave empty to capture all IPs

### 3. PCAP File (Optional)

- Check "Save to PCAP file" to enable PCAP export
- Click "Browse..." to select a save location
- The file will be created automatically when capture starts

### 4. Start Capture

- Click "Start Capture" to begin capturing packets
- The status bar will show "Capturing..."
- Packets will appear in the table in real-time

### 5. View Packets

The packet table displays:
- **Time**: Timestamp when packet was captured
- **Source**: Source IP address and port (if applicable)
- **Destination**: Destination IP address and port (if applicable)
- **Protocol**: Protocol type (TCP, UDP, ICMP, etc.)
- **Info**: Additional protocol-specific information

### 6. Monitor Statistics

The statistics panel shows:
- **Total Packets**: All packets captured
- **TCP Packets**: TCP protocol packets
- **UDP Packets**: UDP protocol packets
- **ICMP Packets**: ICMP protocol packets
- **Filtered Packets**: Packets matching your filters
- **Errors**: Parsing or capture errors

### 7. Stop Capture

- Click "Stop Capture" to end the capture session
- The PCAP file (if enabled) will be finalized and closed
- Statistics remain visible until cleared

### 8. Clear Log

- Click "Clear Log" to remove all displayed packets
- Statistics are also reset

## Tips

1. **Performance**: The display is limited to 1000 packets to prevent memory issues. Older packets are automatically removed.

2. **Filtering**: Use filters to reduce noise and focus on specific traffic patterns.

3. **PCAP Files**: PCAP files can be opened in Wireshark, tcpdump, or other packet analysis tools.

4. **Administrator Rights**: Always run as Administrator (Windows) or with sudo (Linux/macOS) for proper raw socket access.

5. **Interface Selection**: If you have multiple network interfaces, select the one you want to monitor.

## Troubleshooting

### "Administrator privileges required" Error

- **Windows**: Right-click PowerShell/CMD and select "Run as Administrator"
- **Linux/macOS**: Use `sudo` command

### "No active network interfaces found" Error

- Ensure your network adapter is enabled
- Check that you have at least one active network connection
- Restart the application

### No Packets Appearing

- Verify network activity is occurring
- Check that filters aren't too restrictive
- Ensure the correct interface is selected
- Check firewall settings

### Application Freezes

- Stop the capture and restart
- Check system resources (CPU/memory)
- Reduce the number of displayed packets by using filters

## Keyboard Shortcuts

- **Ctrl+C**: Stop capture (if running in terminal)
- **Escape**: Close application (when not capturing)

## Differences from CLI Version

The GUI version provides the same core functionality as the CLI version (`sniffer.py`) but with:
- Visual interface instead of command-line arguments
- Real-time packet display
- Live statistics
- Easier filter configuration
- Better for interactive use

The CLI version is still available for:
- Scripting and automation
- Server environments without GUI
- Quick captures from command line
