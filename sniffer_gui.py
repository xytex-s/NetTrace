#!/usr/bin/env python3
"""
Network Packet Sniffer - Windows GUI Application
------------------------------------------------

A modern Windows-style GUI for the network packet sniffer.
Provides an intuitive interface for packet capture and analysis.

Author: xytex-s
License: MIT
"""

import os
import sys
import socket
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
import logging
from typing import Optional

# Import sniffer components
from sniffer import (
    PacketFilter, SecurityError, get_interfaces,
    make_sniffer_socket, parse_ether_header, parse_ip_header,
    parse_tcp_header, parse_udp_header, parse_icmp_header,
    PCAPWriter, PACKET_SIZE
)

# Configure logging for GUI (less verbose)
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("sniffer_gui")


class PacketSnifferGUI:
    """Main GUI application for packet sniffer."""

    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # State variables
        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self.socket = None
        self.writer: Optional[PCAPWriter] = None
        self.running = threading.Event()
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'filtered_packets': 0,
            'errors': 0
        }
        
        # Setup UI
        self._setup_ui()
        self._load_interfaces()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _setup_ui(self):
        """Create and layout all UI components."""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # === Control Panel (Left Side) ===
        control_frame = ttk.LabelFrame(main_frame, text="Capture Controls", padding="10")
        control_frame.grid(row=0, column=0, rowspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))

        # Interface selection
        ttk.Label(control_frame, text="Network Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, 
                                           state="readonly", width=25)
        self.interface_combo.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        control_frame.columnconfigure(0, weight=1)

        # Protocol filter
        ttk.Label(control_frame, text="Protocol Filter:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.proto_var = tk.StringVar(value="All")
        proto_frame = ttk.Frame(control_frame)
        proto_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)
        ttk.Radiobutton(proto_frame, text="All", variable=self.proto_var, value="All").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(proto_frame, text="TCP", variable=self.proto_var, value="tcp").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(proto_frame, text="UDP", variable=self.proto_var, value="udp").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(proto_frame, text="ICMP", variable=self.proto_var, value="icmp").pack(side=tk.LEFT, padx=5)

        # Port filter
        ttk.Label(control_frame, text="Port Filter:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.port_var = tk.StringVar()
        port_entry = ttk.Entry(control_frame, textvariable=self.port_var, width=25)
        port_entry.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=5)
        ttk.Label(control_frame, text="(Leave empty for all ports)", 
                 font=("TkDefaultFont", 8)).grid(row=6, column=0, sticky=tk.W)

        # IP filter
        ttk.Label(control_frame, text="IP Address Filter:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.ip_var = tk.StringVar()
        ip_entry = ttk.Entry(control_frame, textvariable=self.ip_var, width=25)
        ip_entry.grid(row=8, column=0, sticky=(tk.W, tk.E), pady=5)
        ttk.Label(control_frame, text="(Leave empty for all IPs)", 
                 font=("TkDefaultFont", 8)).grid(row=9, column=0, sticky=tk.W)

        # PCAP file option
        ttk.Separator(control_frame, orient=tk.HORIZONTAL).grid(row=10, column=0, sticky=(tk.W, tk.E), pady=10)
        self.pcap_enabled = tk.BooleanVar()
        pcap_check = ttk.Checkbutton(control_frame, text="Save to PCAP file", 
                                     variable=self.pcap_enabled, command=self._toggle_pcap)
        pcap_check.grid(row=11, column=0, sticky=tk.W, pady=5)
        self.pcap_path_var = tk.StringVar()
        pcap_frame = ttk.Frame(control_frame)
        pcap_frame.grid(row=12, column=0, sticky=(tk.W, tk.E), pady=5)
        ttk.Entry(pcap_frame, textvariable=self.pcap_path_var, width=20, state="disabled").pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(pcap_frame, text="Browse...", command=self._browse_pcap, 
                  state="disabled", width=8).pack(side=tk.LEFT, padx=(5, 0))
        self.pcap_browse_btn = pcap_frame.children['!button']

        # Control buttons
        ttk.Separator(control_frame, orient=tk.HORIZONTAL).grid(row=13, column=0, sticky=(tk.W, tk.E), pady=10)
        self.start_btn = ttk.Button(control_frame, text="Start Capture", 
                                    command=self._start_capture, width=20)
        self.start_btn.grid(row=14, column=0, pady=5)
        self.stop_btn = ttk.Button(control_frame, text="Stop Capture", 
                                   command=self._stop_capture, state="disabled", width=20)
        self.stop_btn.grid(row=15, column=0, pady=5)
        ttk.Button(control_frame, text="Clear Log", command=self._clear_log, width=20).grid(row=16, column=0, pady=5)

        # === Statistics Panel ===
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N), padx=(0, 10))

        self.stats_labels = {}
        stats_data = [
            ("Total Packets:", "total_packets"),
            ("TCP Packets:", "tcp_packets"),
            ("UDP Packets:", "udp_packets"),
            ("ICMP Packets:", "icmp_packets"),
            ("Filtered Packets:", "filtered_packets"),
            ("Errors:", "errors")
        ]

        for i, (label, key) in enumerate(stats_data):
            row_frame = ttk.Frame(stats_frame)
            row_frame.grid(row=i, column=0, sticky=(tk.W, tk.E), pady=2)
            ttk.Label(row_frame, text=label, width=18).pack(side=tk.LEFT)
            stat_label = ttk.Label(row_frame, text="0", font=("TkDefaultFont", 9, "bold"))
            stat_label.pack(side=tk.LEFT)
            self.stats_labels[key] = stat_label

        # === Packet Display Area ===
        display_frame = ttk.LabelFrame(main_frame, text="Captured Packets", padding="5")
        display_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10), pady=(10, 0))
        display_frame.columnconfigure(0, weight=1)
        display_frame.rowconfigure(0, weight=1)

        # Create treeview for packet display
        columns = ("Time", "Source", "Destination", "Protocol", "Info")
        self.packet_tree = ttk.Treeview(display_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        self.packet_tree.heading("Time", text="Time")
        self.packet_tree.heading("Source", text="Source")
        self.packet_tree.heading("Destination", text="Destination")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.heading("Info", text="Info")
        
        self.packet_tree.column("Time", width=120, anchor=tk.W)
        self.packet_tree.column("Source", width=150, anchor=tk.W)
        self.packet_tree.column("Destination", width=150, anchor=tk.W)
        self.packet_tree.column("Protocol", width=80, anchor=tk.CENTER)
        self.packet_tree.column("Info", width=200, anchor=tk.W)

        # Scrollbars
        v_scrollbar = ttk.Scrollbar(display_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        h_scrollbar = ttk.Scrollbar(display_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.packet_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))

        # === Status Bar ===
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(10, 0))
        status_frame.columnconfigure(0, weight=1)

        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, 
                                relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status_label.grid(row=0, column=0, sticky=(tk.W, tk.E))

    def _load_interfaces(self):
        """Load available network interfaces."""
        try:
            ifaces = get_interfaces()
            interface_list = [f"{name} ({ip})" for name, ip in ifaces]
            self.interface_combo['values'] = interface_list
            if interface_list:
                self.interface_combo.current(0)
                self.interface_names = ifaces  # Store for later use
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load interfaces: {e}")
            self.status_var.set(f"Error: {e}")

    def _toggle_pcap(self):
        """Enable/disable PCAP file selection."""
        state = "normal" if self.pcap_enabled.get() else "disabled"
        self.pcap_path_var.set("")
        for widget in [self.pcap_browse_btn]:
            widget.configure(state=state)

    def _browse_pcap(self):
        """Open file dialog for PCAP file selection."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        if filename:
            self.pcap_path_var.set(filename)

    def _clear_log(self):
        """Clear the packet display."""
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self._reset_stats()

    def _reset_stats(self):
        """Reset statistics counters."""
        for key in self.stats:
            self.stats[key] = 0
        self._update_stats_display()

    def _update_stats_display(self):
        """Update statistics display labels."""
        for key, label in self.stats_labels.items():
            label.config(text=str(self.stats[key]))

    def _add_packet_to_display(self, time_str, src, dst, proto, info):
        """Add a packet to the display treeview."""
        self.packet_tree.insert("", tk.END, values=(time_str, src, dst, proto, info))
        # Auto-scroll to bottom
        self.packet_tree.see(self.packet_tree.get_children()[-1] if self.packet_tree.get_children() else "")
        # Limit to 1000 packets to prevent memory issues
        if len(self.packet_tree.get_children()) > 1000:
            self.packet_tree.delete(self.packet_tree.get_children()[0])

    def _start_capture(self):
        """Start packet capture."""
        if self.is_capturing:
            return

        # Validate inputs
        if not self.interface_var.get():
            messagebox.showerror("Error", "Please select a network interface")
            return

        port_str = self.port_var.get().strip()
        if port_str:
            try:
                port = int(port_str)
                if not (1 <= port <= 65535):
                    raise ValueError("Port out of range")
            except ValueError:
                messagebox.showerror("Error", "Invalid port number (1-65535)")
                return

        if self.pcap_enabled.get() and not self.pcap_path_var.get():
            messagebox.showerror("Error", "Please specify a PCAP file path")
            return

        # Check admin privileges
        if os.name == 'nt':
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    messagebox.showerror("Error", 
                        "Administrator privileges required!\n\n"
                        "Please run this program as Administrator.")
                    return
            except Exception:
                pass

        # Update UI
        self.is_capturing = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("Capturing...")
        self.running.set()

        # Start capture thread
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()

    def _stop_capture(self):
        """Stop packet capture."""
        if not self.is_capturing:
            return

        self.is_capturing = False
        self.running.clear()
        self.status_var.set("Stopping...")

        # Wait for thread to finish (with timeout)
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)

        # Close resources
        if self.socket:
            try:
                if os.name == 'nt':
                    self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.socket.close()
            except Exception:
                pass
            self.socket = None

        if self.writer:
            self.writer.close()
            self.writer = None

        # Update UI
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set("Stopped")

    def _capture_loop(self):
        """Main capture loop running in separate thread."""
        
        # Create mock args object for socket creation
        class Args:
            def __init__(self, interface):
                self.interface = interface

        try:
            # Get selected interface name
            selected = self.interface_var.get()
            iface_name = selected.split(" (")[0] if " (" in selected else selected
            args = Args(iface_name)

            # Initialize PCAP writer if enabled
            if self.pcap_enabled.get():
                try:
                    self.writer = PCAPWriter(self.pcap_path_var.get())
                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to create PCAP file: {e}"))
                    self.root.after(0, self._stop_capture)
                    return

            # Create socket
            with make_sniffer_socket(args) as sn:
                self.socket = sn
                sn.settimeout(1.0)

                # Get filters
                proto = self.proto_var.get() if self.proto_var.get() != "All" else None
                port = int(self.port_var.get()) if self.port_var.get().strip() else None
                ip = self.ip_var.get().strip() if self.ip_var.get().strip() else None
                filters = PacketFilter(proto, port, ip)

                while self.running.is_set():
                    try:
                        data, addr = sn.recvfrom(PACKET_SIZE)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"Socket error: {e}")
                        self.stats['errors'] += 1
                        self.root.after(0, self._update_stats_display)
                        break

                    try:
                        # Parse packet
                        if os.name != 'nt':
                            d_mac, s_mac, eth_proto, payload = parse_ether_header(data)
                            if eth_proto != 8:  # not IPv4
                                continue
                            version, ihl, ttl, proto_num, src_ip, dst_ip, ip_data = parse_ip_header(payload)
                        else:
                            version, ihl, ttl, proto_num, src_ip, dst_ip, ip_data = parse_ip_header(data)

                        # Update stats
                        self.stats['total_packets'] += 1

                        # Parse protocol-specific data
                        proto_name = "Unknown"
                        info = ""
                        s_port = d_port = 0

                        if proto_num == 6:  # TCP
                            s_port, d_port, *_ = parse_tcp_header(ip_data)
                            proto_name = "TCP"
                            info = f"Port {s_port} -> {d_port}"
                            self.stats['tcp_packets'] += 1

                        elif proto_num == 17:  # UDP
                            s_port, d_port, _, _ = parse_udp_header(ip_data)
                            proto_name = "UDP"
                            info = f"Port {s_port} -> {d_port}"
                            self.stats['udp_packets'] += 1

                        elif proto_num == 1:  # ICMP
                            icmp_type, code, _, _ = parse_icmp_header(ip_data)
                            proto_name = "ICMP"
                            info = f"Type {icmp_type}, Code {code}"
                            self.stats['icmp_packets'] += 1

                        # Check filters
                        if filters.matches(proto_num, s_port, d_port, src_ip, dst_ip):
                            self.stats['filtered_packets'] += 1
                            
                            # Format source/destination
                            if s_port and d_port:
                                src_str = f"{src_ip}:{s_port}"
                                dst_str = f"{dst_ip}:{d_port}"
                            else:
                                src_str = src_ip
                                dst_str = dst_ip

                            # Add to display
                            time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                            self.root.after(0, lambda: self._add_packet_to_display(
                                time_str, src_str, dst_str, proto_name, info
                            ))

                        # Write to PCAP if enabled
                        if self.writer:
                            try:
                                self.writer.write_packet(data, is_windows=(os.name == 'nt'))
                            except Exception as e:
                                logger.error(f"PCAP write error: {e}")
                                self.stats['errors'] += 1

                        # Update stats display periodically
                        if self.stats['total_packets'] % 10 == 0:
                            self.root.after(0, self._update_stats_display)

                    except Exception as e:
                        # Skip malformed packets
                        logger.debug(f"Parse error: {e}")
                        self.stats['errors'] += 1
                        continue

        except SecurityError as e:
            self.root.after(0, lambda: messagebox.showerror("Permission Error", str(e)))
            self.root.after(0, self._stop_capture)
        except Exception as e:
            logger.exception("Capture error:")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Capture failed: {e}"))
            self.root.after(0, self._stop_capture)
        finally:
            if self.writer:
                self.writer.close()
                self.writer = None

    def _on_closing(self):
        """Handle window close event."""
        if self.is_capturing:
            if messagebox.askokcancel("Quit", "Capture is running. Stop and quit?"):
                self._stop_capture()
                self.root.after(500, self.root.destroy)
        else:
            self.root.destroy()


def main():
    """Main entry point for GUI application."""
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
