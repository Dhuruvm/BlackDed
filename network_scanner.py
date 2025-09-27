#!/usr/bin/env python3
"""
BlackDeD Network Scanner Module
Advanced network discovery and port scanning tools
"""

import socket
import threading
import subprocess
import time
import ipaddress
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, TaskID
from rich.live import Live
import netifaces
import psutil
import nmap

console = Console(style="on black")

class NetworkScanner:
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        self.scan_results = []
        self.threads = []
        
    def get_local_ip(self):
        """Get the local IP address"""
        try:
            # Connect to Google DNS to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def get_network_interfaces(self):
        """Get all network interfaces and their details"""
        interfaces = []
        
        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        interfaces.append({
                            'interface': interface,
                            'ip': addr.get('addr', 'N/A'),
                            'netmask': addr.get('netmask', 'N/A'),
                            'broadcast': addr.get('broadcast', 'N/A')
                        })
            except Exception as e:
                continue
                
        return interfaces
    
    def calculate_network_range(self, ip, netmask):
        """Calculate network range from IP and netmask"""
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network.network_address), str(network.broadcast_address), str(network)
        except Exception:
            return None, None, None
    
    def ping_host(self, host):
        """Ping a single host to check if it's alive"""
        try:
            # Use ping command (cross-platform)
            cmd = ['ping', '-c', '1', '-W', '1000', host] if 'linux' in str(psutil.LINUX).lower() else ['ping', '-n', '1', '-w', '1000', host]
            result = subprocess.run(cmd, capture_output=True, timeout=2)
            return result.returncode == 0
        except Exception:
            return False
    
    def scan_port(self, host, port, timeout=1):
        """Scan a single port on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                # Try to grab banner
                try:
                    banner_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    banner_sock.settimeout(2)
                    banner_sock.connect((host, port))
                    banner = banner_sock.recv(1024).decode('utf-8', 'ignore').strip()
                    banner_sock.close()
                    return True, banner[:100] if banner else "No banner"
                except:
                    return True, "Open"
            return False, ""
        except Exception:
            return False, ""
    
    def get_service_name(self, port):
        """Get service name for a port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Alt"
        }
        return services.get(port, "Unknown")
    
    def network_discovery(self):
        """Discover hosts on the local network"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🌐 Network Discovery Module")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        # Get network interfaces
        interfaces = self.get_network_interfaces()
        if not interfaces:
            console.print(f"{Fore.RED}❌ No network interfaces found!")
            return
        
        # Display interface information (Kali Linux style)
        interface_table = Table(show_header=True, header_style="bold green on black", style="on black")
        interface_table.add_column("Interface", style="green on black")
        interface_table.add_column("IP Address", style="bright_green on black")
        interface_table.add_column("Netmask", style="green on black")
        interface_table.add_column("Broadcast", style="white on black")
        
        for iface in interfaces:
            if iface['ip'] != '127.0.0.1':  # Skip localhost
                interface_table.add_row(
                    iface['interface'],
                    iface['ip'],
                    iface['netmask'],
                    iface['broadcast']
                )
        
        panel = Panel(interface_table, title="[green on black]Network Interfaces[/green on black]", border_style="green on black", style="on black")
        console.print(panel)
        
        # Let user select interface for scanning
        valid_interfaces = [iface for iface in interfaces if iface['ip'] != '127.0.0.1']
        if not valid_interfaces:
            console.print(f"{Fore.RED}❌ No valid network interfaces found!")
            return
        
        print(f"\n{Back.BLACK}{Fore.GREEN}[*] Available interfaces:")
        for i, iface in enumerate(valid_interfaces, 1):
            print(f"{Back.BLACK}{Fore.GREEN}{i}. {iface['interface']} ({iface['ip']})")
        
        try:
            choice = int(input(f"\n{Back.BLACK}{Fore.GREEN}root@blackded:~# Select interface (1-{len(valid_interfaces)}): ")) - 1
            selected_interface = valid_interfaces[choice]
        except (ValueError, IndexError):
            console.print(f"{Fore.RED}❌ Invalid selection!")
            return
        
        # Calculate network range
        network_addr, broadcast_addr, network_range = self.calculate_network_range(
            selected_interface['ip'], selected_interface['netmask']
        )
        
        if not network_range:
            console.print(f"{Fore.RED}❌ Could not calculate network range!")
            return
        
        console.print(f"\n{Back.BLACK}{Fore.GREEN}[+] Scanning network: {network_range}")
        
        # Generate host list
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = [str(ip) for ip in network.hosts()][:254]  # Limit to 254 hosts
        except Exception as e:
            console.print(f"{Fore.RED}❌ Error generating host list: {e}")
            return
        
        # Scan for alive hosts
        alive_hosts = []
        with Progress() as progress:
            task = progress.add_task("[cyan]Discovering hosts...", total=len(hosts))
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self.ping_host, host): host for host in hosts}
                
                for future in futures:
                    host = futures[future]
                    if future.result():
                        alive_hosts.append(host)
                    progress.advance(task)
        
        # Display results
        if alive_hosts:
            results_table = Table(show_header=True, header_style="bold green on black", style="on black")
            results_table.add_column("Host", style="bright_green on black")
            results_table.add_column("Status", style="green on black")
            results_table.add_column("Response Time", style="white on black")
            
            for host in alive_hosts:
                results_table.add_row(host, "✅ Alive", "< 1s")
            
            panel = Panel(results_table, title=f"[green on black]Discovery Results ({len(alive_hosts)} hosts found)[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
            
            return alive_hosts
        else:
            console.print(f"{Fore.YELLOW}⚠️ No alive hosts found on the network.")
            return []
    
    def port_scanner(self, target_host=None):
        """Advanced port scanner"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🔍 Advanced Port Scanner")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        if not target_host:
            target_host = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter target host/IP: ").strip()
        
        if not target_host:
            console.print(f"{Fore.RED}❌ No target specified!")
            return
        
        # Check if host is alive
        if not self.ping_host(target_host):
            console.print(f"{Fore.YELLOW}⚠️ Host {target_host} appears to be down or not responding to ping.")
            proceed = input(f"{Fore.CYAN}Continue with port scan anyway? (y/n): ").lower().strip()
            if proceed != 'y':
                return
        
        # Scan options
        print(f"\n{Fore.GREEN}Scan Options:")
        print(f"{Fore.YELLOW}1. Quick Scan (Common Ports)")
        print(f"{Fore.YELLOW}2. Full Scan (1-65535)")
        print(f"{Fore.YELLOW}3. Custom Port Range")
        print(f"{Fore.YELLOW}4. Specific Ports")
        
        try:
            scan_type = input(f"\n{Fore.CYAN}Select scan type (1-4): ").strip()
        except KeyboardInterrupt:
            return
        
        ports_to_scan = []
        
        if scan_type == "1":
            ports_to_scan = self.common_ports
        elif scan_type == "2":
            ports_to_scan = list(range(1, 65536))
        elif scan_type == "3":
            try:
                start_port = int(input(f"{Fore.YELLOW}Start port: "))
                end_port = int(input(f"{Fore.YELLOW}End port: "))
                ports_to_scan = list(range(start_port, end_port + 1))
            except ValueError:
                console.print(f"{Fore.RED}❌ Invalid port range!")
                return
        elif scan_type == "4":
            try:
                ports_input = input(f"{Fore.YELLOW}Enter ports (comma-separated): ")
                ports_to_scan = [int(p.strip()) for p in ports_input.split(',')]
            except ValueError:
                console.print(f"{Fore.RED}❌ Invalid port list!")
                return
        else:
            console.print(f"{Fore.RED}❌ Invalid scan type!")
            return
        
        # Perform scan
        open_ports = []
        total_ports = len(ports_to_scan)
        
        console.print(f"\n{Fore.GREEN}🎯 Scanning {total_ports} ports on {target_host}")
        
        with Progress() as progress:
            task = progress.add_task(f"[cyan]Scanning ports...", total=total_ports)
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(self.scan_port, target_host, port): port for port in ports_to_scan}
                
                for future in futures:
                    port = futures[future]
                    is_open, banner = future.result()
                    if is_open:
                        open_ports.append({
                            'port': port,
                            'service': self.get_service_name(port),
                            'banner': banner
                        })
                    progress.advance(task)
        
        # Display results
        if open_ports:
            results_table = Table(show_header=True, header_style="bold bright_green")
            results_table.add_column("Port", style="bright_yellow", justify="center")
            results_table.add_column("Service", style="bright_cyan")
            results_table.add_column("State", style="bright_green")
            results_table.add_column("Banner", style="bright_white")
            
            for port_info in open_ports:
                results_table.add_row(
                    str(port_info['port']),
                    port_info['service'],
                    "✅ Open",
                    port_info['banner'][:50] + "..." if len(port_info['banner']) > 50 else port_info['banner']
                )
            
            panel = Panel(results_table, title=f"[bright_green]Port Scan Results for {target_host} ({len(open_ports)} open ports)[/bright_green]", border_style="green")
            console.print(panel)
            
            # Save results
            self.save_scan_results(target_host, open_ports)
        else:
            console.print(f"{Fore.YELLOW}⚠️ No open ports found on {target_host}")
    
    def nmap_scanner(self):
        """Advanced Nmap scanner"""
        console.print(f"\n{Fore.CYAN}{Style.BRIGHT}🛡️ Advanced Nmap Scanner")
        console.print("=" * 60)
        
        target = input(f"{Fore.YELLOW}Enter target (IP/hostname/range): ").strip()
        if not target:
            console.print(f"{Fore.RED}❌ No target specified!")
            return
        
        # Scan options
        print(f"\n{Fore.GREEN}Nmap Scan Types:")
        print(f"{Fore.YELLOW}1. TCP SYN Scan (-sS)")
        print(f"{Fore.YELLOW}2. TCP Connect Scan (-sT)")
        print(f"{Fore.YELLOW}3. UDP Scan (-sU)")
        print(f"{Fore.YELLOW}4. Comprehensive Scan (-sS -sV -O)")
        print(f"{Fore.YELLOW}5. Stealth Scan (-sS -f -D RND:10)")
        
        try:
            scan_type = input(f"\n{Fore.CYAN}Select scan type (1-5): ").strip()
        except KeyboardInterrupt:
            return
        
        # Configure nmap arguments
        nm = nmap.PortScanner()
        arguments = ""
        
        if scan_type == "1":
            arguments = "-sS"
        elif scan_type == "2":
            arguments = "-sT"
        elif scan_type == "3":
            arguments = "-sU"
        elif scan_type == "4":
            arguments = "-sS -sV -O"
        elif scan_type == "5":
            arguments = "-sS -f -D RND:10"
        else:
            console.print(f"{Fore.RED}❌ Invalid scan type!")
            return
        
        try:
            console.print(f"\n{Fore.GREEN}🎯 Running Nmap scan: nmap {arguments} {target}")
            console.print(f"{Fore.YELLOW}⏳ This may take a while...")
            
            # Run scan
            nm.scan(target, arguments=arguments)
            
            # Display results
            for host in nm.all_hosts():
                console.print(f"\n{Fore.CYAN}📡 Host: {host} ({nm[host].hostname()})")
                console.print(f"{Fore.GREEN}State: {nm[host].state()}")
                
                # Protocol info
                for protocol in nm[host].all_protocols():
                    ports = nm[host][protocol].keys()
                    
                    if ports:
                        port_table = Table(show_header=True, header_style="bold bright_green")
                        port_table.add_column("Port", style="bright_yellow", justify="center")
                        port_table.add_column("State", style="bright_green")
                        port_table.add_column("Service", style="bright_cyan")
                        port_table.add_column("Version", style="bright_white")
                        
                        for port in ports:
                            port_info = nm[host][protocol][port]
                            port_table.add_row(
                                str(port),
                                port_info['state'],
                                port_info.get('name', 'unknown'),
                                port_info.get('version', 'N/A')
                            )
                        
                        panel = Panel(port_table, title=f"[bright_green]{protocol.upper()} Ports[/bright_green]", border_style="green")
                        console.print(panel)
                
                # OS Detection if available
                if 'osclass' in nm[host]:
                    console.print(f"{Fore.MAGENTA}🖥️ OS Detection:")
                    for osclass in nm[host]['osclass']:
                        console.print(f"  {osclass['osfamily']} {osclass.get('osgen', '')} ({osclass['accuracy']}% accuracy)")
                        
        except Exception as e:
            console.print(f"{Fore.RED}❌ Nmap scan failed: {str(e)}")
    
    def vulnerability_scanner(self):
        """Basic vulnerability scanning"""
        console.print(f"\n{Fore.CYAN}{Style.BRIGHT}🔍 Vulnerability Scanner")
        console.print("=" * 60)
        
        target = input(f"{Fore.YELLOW}Enter target host: ").strip()
        if not target:
            console.print(f"{Fore.RED}❌ No target specified!")
            return
        
        console.print(f"{Fore.GREEN}🎯 Scanning {target} for common vulnerabilities...")
        
        # Check for common vulnerabilities
        vulnerabilities = []
        
        # Check for open telnet
        is_open, _ = self.scan_port(target, 23)
        if is_open:
            vulnerabilities.append({
                'service': 'Telnet (Port 23)',
                'risk': 'HIGH',
                'description': 'Telnet sends data in plaintext and is vulnerable to interception'
            })
        
        # Check for FTP
        is_open, banner = self.scan_port(target, 21)
        if is_open:
            vulnerabilities.append({
                'service': 'FTP (Port 21)',
                'risk': 'MEDIUM',
                'description': 'FTP may allow anonymous access or send credentials in plaintext'
            })
        
        # Check for SSH with version detection
        is_open, banner = self.scan_port(target, 22)
        if is_open and banner:
            if 'OpenSSH' in banner:
                vulnerabilities.append({
                    'service': 'SSH (Port 22)',
                    'risk': 'INFO',
                    'description': f'SSH service detected: {banner[:50]}'
                })
        
        # Check for HTTP
        is_open, _ = self.scan_port(target, 80)
        if is_open:
            vulnerabilities.append({
                'service': 'HTTP (Port 80)',
                'risk': 'MEDIUM',
                'description': 'HTTP traffic is unencrypted and may expose sensitive data'
            })
        
        # Check for RDP
        is_open, _ = self.scan_port(target, 3389)
        if is_open:
            vulnerabilities.append({
                'service': 'RDP (Port 3389)',
                'risk': 'HIGH',
                'description': 'RDP exposed to network, potential for brute force attacks'
            })
        
        # Display results
        if vulnerabilities:
            vuln_table = Table(show_header=True, header_style="bold bright_red")
            vuln_table.add_column("Service", style="bright_yellow")
            vuln_table.add_column("Risk Level", style="bright_red")
            vuln_table.add_column("Description", style="bright_white")
            
            for vuln in vulnerabilities:
                risk_color = "bright_red" if vuln['risk'] == 'HIGH' else "bright_yellow" if vuln['risk'] == 'MEDIUM' else "bright_green"
                vuln_table.add_row(
                    vuln['service'],
                    f"[{risk_color}]{vuln['risk']}[/{risk_color}]",
                    vuln['description']
                )
            
            panel = Panel(vuln_table, title=f"[bright_red]Vulnerability Scan Results for {target}[/bright_red]", border_style="red")
            console.print(panel)
        else:
            console.print(f"{Fore.GREEN}✅ No obvious vulnerabilities detected on {target}")
    
    def save_scan_results(self, target, results):
        """Save scan results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"blackded_scan_{target}_{timestamp}.json"
        
        scan_data = {
            'target': target,
            'timestamp': timestamp,
            'results': results
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(scan_data, f, indent=2)
            console.print(f"\n{Fore.GREEN}💾 Results saved to: {filename}")
        except Exception as e:
            console.print(f"{Fore.RED}❌ Failed to save results: {e}")
    
    def show_menu(self):
        """Display network scanner menu"""
        while True:
            console.print(f"\n{Fore.CYAN}{Style.BRIGHT}🌐 NETWORK SCANNING MODULE")
            console.print("=" * 50)
            
            options = [
                ("1", "🔍 Network Discovery", "Discover hosts on local network"),
                ("2", "🎯 Port Scanner", "Scan ports on target host"),
                ("3", "🛡️ Advanced Nmap Scanner", "Use Nmap for comprehensive scanning"),
                ("4", "⚠️ Vulnerability Scanner", "Basic vulnerability detection"),
                ("5", "📊 Show Network Interfaces", "Display network interface information"),
                ("0", "🔙 Back to Main Menu", "Return to BlackDeD main menu")
            ]
            
            menu_table = Table(show_header=True, header_style="bold green on black", style="on black")
            menu_table.add_column("Option", style="green on black", justify="center", width=8)
            menu_table.add_column("Tool", style="bright_green on black", width=25)
            menu_table.add_column("Description", style="white on black", width=40)
            
            for option, tool, description in options:
                menu_table.add_row(option, tool, description)
            
            panel = Panel(menu_table, title="[green on black]Network Scanning Tools[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
            
            try:
                choice = input(f"\n{Back.BLACK}{Fore.GREEN}root@blackded:~# Select option: ").strip()
                
                if choice == "1":
                    self.network_discovery()
                elif choice == "2":
                    self.port_scanner()
                elif choice == "3":
                    self.nmap_scanner()
                elif choice == "4":
                    self.vulnerability_scanner()
                elif choice == "5":
                    self.show_network_interfaces()
                elif choice == "0":
                    break
                else:
                    console.print(f"{Fore.RED}❌ Invalid option!")
                
                if choice != "0":
                    input(f"\n{Fore.WHITE}Press Enter to continue...")
                    
            except KeyboardInterrupt:
                console.print(f"\n{Fore.YELLOW}Returning to main menu...")
                break
    
    def show_network_interfaces(self):
        """Display detailed network interface information"""
        console.print(f"\n{Fore.CYAN}{Style.BRIGHT}📡 Network Interface Information")
        console.print("=" * 60)
        
        interfaces = self.get_network_interfaces()
        
        for i, iface in enumerate(interfaces, 1):
            interface_info = Table(show_header=False, border_style="bright_cyan")
            interface_info.add_column("Property", style="bright_yellow", justify="right")
            interface_info.add_column("Value", style="bright_white")
            
            interface_info.add_row("Interface", iface['interface'])
            interface_info.add_row("IP Address", iface['ip'])
            interface_info.add_row("Netmask", iface['netmask'])
            interface_info.add_row("Broadcast", iface['broadcast'])
            
            # Calculate network range
            if iface['ip'] != '127.0.0.1':
                network_addr, broadcast_addr, network_range = self.calculate_network_range(iface['ip'], iface['netmask'])
                if network_range:
                    interface_info.add_row("Network Range", network_range)
            
            panel = Panel(interface_info, title=f"[bright_green]Interface {i}: {iface['interface']}[/bright_green]", border_style="green")
            console.print(panel)

def main():
    scanner = NetworkScanner()
    scanner.show_menu()

if __name__ == "__main__":
    main()