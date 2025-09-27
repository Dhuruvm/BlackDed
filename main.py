#!/usr/bin/env python3
"""
BlackDeD - Advanced Ethical Hacking Toolkit
Designed for Security Professionals and Penetration Testers
Optimized for Termux and Linux environments
"""

import os
import sys
import time
import platform
from colorama import init, Fore, Back, Style
from pyfiglet import Figlet
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import psutil

# Initialize colorama for cross-platform colored output
init(autoreset=True)
# Kali Linux-style black console with green theme
console = Console(style="on black")

class BlackDeD:
    def __init__(self):
        self.version = "1.0.0"
        self.author = "BlackDeD Security Team"
        self.dependencies_checked = False
        self.clear_screen()
        
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
    def print_banner(self):
        """Display the Kali Linux-style ASCII art banner with black background"""
        self.clear_screen()
        
        # Set terminal background to black (Kali Linux style)
        print(f"{Back.BLACK}{Fore.GREEN}", end="")
        
        # Create Kali Linux-style banner
        f = Figlet(font='slant')
        banner = f.renderText('BlackDeD')
        
        # Print banner with Kali Linux green on black
        lines = banner.split('\n')
        
        print(f"{Back.BLACK}")
        for line in lines:
            print(f"{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}{line}")
        
        # Kali Linux-style subtitle with black background
        subtitle = f"""
{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}┌─────────────────────────────────────────────────────────────────────────────┐
{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}│                 Advanced Ethical Hacking Toolkit                           │
{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}│                    for Security Professionals                              │
{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}├─────────────────────────────────────────────────────────────────────────────┤
{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}│  Version: {self.version:<10} │  Author: {self.author:<25}  │
{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}│  Optimized for Termux & Linux Environments                                 │
{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}└─────────────────────────────────────────────────────────────────────────────┘
"""
        print(subtitle)
        
        # System information panel
        self.show_system_info()
        
    def show_system_info(self):
        """Display system information in a styled panel"""
        # Get system information
        system_info = {
            "OS": platform.system() + " " + platform.release(),
            "Architecture": platform.architecture()[0],
            "Python Version": platform.python_version(),
            "CPU Count": str(os.cpu_count()),
            "Memory": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB",
            "Available Memory": f"{round(psutil.virtual_memory().available / (1024**3), 2)} GB"
        }
        
        # Create Kali Linux-style table for system info
        table = Table(show_header=False, show_lines=True, border_style="green on black")
        table.add_column("Property", style="green on black", justify="right")
        table.add_column("Value", style="bright_green on black")
        
        for key, value in system_info.items():
            table.add_row(key, value)
        
        panel = Panel(
            table,
            title="[green on black]⚡ System Information ⚡[/green on black]",
            border_style="green on black",
            style="on black",
            padding=(1, 2)
        )
        
        console.print(panel)
        print()
    
    def check_dependencies(self):
        """Check for required dependencies and tools"""
        if self.dependencies_checked:
            return True
        
        print(f"{Back.BLACK}{Fore.GREEN}[*] Checking system dependencies...")
        missing_deps = []
        
        # Check Python packages
        required_packages = {
            'nmap': 'python-nmap',
            'scapy': 'scapy', 
            'paramiko': 'paramiko',
            'cryptography': 'cryptography',
            'netifaces': 'netifaces',
            'psutil': 'psutil'
        }
        
        for pkg, pip_name in required_packages.items():
            try:
                __import__(pkg)
            except ImportError:
                missing_deps.append(f"Python package: {pip_name}")
        
        # Check for nmap binary
        import subprocess
        import shutil
        if not shutil.which('nmap'):
            missing_deps.append("Nmap binary (install with: apt install nmap)")
        
        if missing_deps:
            print(f"{Back.BLACK}{Fore.YELLOW}[!] Missing dependencies detected:")
            for dep in missing_deps:
                print(f"{Back.BLACK}{Fore.YELLOW}  - {dep}")
            print(f"{Back.BLACK}{Fore.YELLOW}[!] Some features may not work without these dependencies.")
            print(f"{Back.BLACK}{Fore.GREEN}[*] Install missing packages and restart BlackDeD for full functionality.")
        else:
            print(f"{Back.BLACK}{Fore.GREEN}[+] All dependencies are available!")
        
        self.dependencies_checked = True
        time.sleep(2)
        return len(missing_deps) == 0
        
    def show_main_menu(self):
        """Display the main menu with all available tools"""
        menu_options = [
            ("1", "🌐 Network Scanning & Discovery", "Port scanning, network mapping, service detection"),
            ("2", "🕸️  Web Application Security", "SQL injection, XSS detection, directory bruteforce"),
            ("3", "📡 Wireless Security Tools", "WiFi scanning, WPS testing, network analysis"),
            ("4", "🎭 Social Engineering Toolkit", "OSINT gathering, email harvesting, phone validation"),
            ("5", "🔒 Cryptography & Password Tools", "Hash cracking, encryption, password generation"),
            ("6", "💻 System Information Gathering", "OS detection, service enumeration, system profiling"),
            ("7", "🔍 Advanced Reconnaissance", "Domain analysis, subdomain discovery, DNS enumeration"),
            ("8", "🛡️  Security Assessment Tools", "Vulnerability scanning, exploit verification"),
            ("9", "⚙️  Configuration & Settings", "Tool configuration, API keys, advanced options"),
            ("0", "❌ Exit BlackDeD", "Close the application safely")
        ]
        
        # Create Kali Linux-style main menu table
        table = Table(show_header=True, header_style="bold green on black", border_style="green on black", style="on black")
        table.add_column("Option", style="bright_green on black", justify="center", width=8)
        table.add_column("Module", style="green on black", width=35)
        table.add_column("Description", style="white on black", width=45)
        
        for option, module, description in menu_options:
            table.add_row(option, module, description)
        
        panel = Panel(
            table,
            title="[green on black]⚔️  BLACKDED MAIN MENU ⚔️[/green on black]",
            subtitle="[green on black]root@blackded:~# Select an option to continue[/green on black]",
            border_style="green on black",
            style="on black",
            padding=(1, 2)
        )
        
        console.print(panel)
        
    def show_loading_animation(self, text="Loading", duration=2):
        """Show a loading animation with custom text"""
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        end_time = time.time() + duration
        
        while time.time() < end_time:
            for char in chars:
                sys.stdout.write(f"\r{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}{char} {text}...")
                sys.stdout.flush()
                time.sleep(0.1)
        
        sys.stdout.write(f"\r{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}✓ {text} Complete!   \n")
        
    def display_warning(self):
        """Display ethical usage warning"""
        warning_text = """
⚠️  LEGAL DISCLAIMER & ETHICAL USAGE WARNING ⚠️

This tool is designed for:
• Authorized penetration testing
• Security research and education  
• Testing your own networks and systems
• Legitimate security assessments

UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS ILLEGAL!
The developers are not responsible for misuse of this tool.
Only use on systems you own or have explicit permission to test.

By continuing, you acknowledge that you will use this tool ethically and legally.
        """
        
        panel = Panel(
            Text(warning_text, style="bright_yellow on black"),
            title="[red on black]⚠️  ETHICAL USAGE WARNING ⚠️[/red on black]",
            border_style="red on black",
            style="on black",
            padding=(1, 2)
        )
        
        console.print(panel)
        
        # Require user acknowledgment (Kali Linux style)
        while True:
            response = input(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}root@blackded:~# Do you agree to use this tool ethically and legally? (yes/no): ").lower().strip()
            if response in ['yes', 'y']:
                print(f"{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}[+] Ethical usage acknowledged. Initializing BlackDeD...")
                break
            elif response in ['no', 'n']:
                print(f"{Back.BLACK}{Fore.RED}{Style.BRIGHT}[-] Access denied. Exiting BlackDeD.")
                sys.exit(0)
            else:
                print(f"{Back.BLACK}{Fore.RED}[!] Please enter 'yes' or 'no'")
        
        time.sleep(1)
        
    def handle_menu_selection(self, choice):
        """Handle user menu selection"""
        if choice == "1":
            self.network_scanning_menu()
        elif choice == "2":
            self.web_security_menu()
        elif choice == "3":
            self.wireless_security_menu()
        elif choice == "4":
            self.social_engineering_menu()
        elif choice == "5":
            self.crypto_tools_menu()
        elif choice == "6":
            self.system_info_menu()
        elif choice == "7":
            self.reconnaissance_menu()
        elif choice == "8":
            self.security_assessment_menu()
        elif choice == "9":
            self.settings_menu()
        elif choice == "0":
            self.exit_application()
        else:
            print(f"{Back.BLACK}{Fore.RED}{Style.BRIGHT}[-] Invalid option! Please select a valid menu option.")
            time.sleep(1)
    
    def network_scanning_menu(self):
        """Network scanning tools submenu"""
        try:
            from network_scanner import NetworkScanner
            scanner = NetworkScanner()
            scanner.show_menu()
        except ImportError as e:
            print(f"{Back.BLACK}{Fore.RED}{Style.BRIGHT}[-] Network scanner module not available: {e}")
            input(f"{Back.BLACK}{Fore.GREEN}[*] Press Enter to return to main menu...")
        except Exception as e:
            print(f"{Back.BLACK}{Fore.RED}{Style.BRIGHT}[-] Error loading network scanner: {e}")
            input(f"{Back.BLACK}{Fore.GREEN}[*] Press Enter to return to main menu...")
        
    def web_security_menu(self):
        """Web application security tools submenu"""
        print(f"{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}\n🕸️ Web Application Security Module")
        print(f"{Back.BLACK}{Fore.GREEN}[*] Coming soon in the next update!")
        input(f"{Back.BLACK}{Fore.GREEN}[*] Press Enter to return to main menu...")
        
    def wireless_security_menu(self):
        """Wireless security tools submenu"""
        print(f"{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}\n📡 Wireless Security Tools Module")
        print(f"{Back.BLACK}{Fore.GREEN}[*] Coming soon in the next update!")
        input(f"{Back.BLACK}{Fore.GREEN}[*] Press Enter to return to main menu...")
        
    def social_engineering_menu(self):
        """Social engineering tools submenu"""
        print(f"{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}\n🎭 Social Engineering Toolkit Module")
        print(f"{Back.BLACK}{Fore.GREEN}[*] Coming soon in the next update!")
        input(f"{Back.BLACK}{Fore.GREEN}[*] Press Enter to return to main menu...")
        
    def crypto_tools_menu(self):
        """Cryptography and password tools submenu"""
        print(f"{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}\n🔒 Cryptography & Password Tools Module")
        print(f"{Back.BLACK}{Fore.GREEN}[*] Coming soon in the next update!")
        input(f"{Back.BLACK}{Fore.GREEN}[*] Press Enter to return to main menu...")
        
    def system_info_menu(self):
        """System information gathering submenu"""
        print(f"{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}\n💻 System Information Gathering Module")
        print(f"{Back.BLACK}{Fore.GREEN}[*] Coming soon in the next update!")
        input(f"{Back.BLACK}{Fore.GREEN}[*] Press Enter to return to main menu...")
        
    def reconnaissance_menu(self):
        """Advanced reconnaissance submenu"""
        print(f"{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}\n🔍 Advanced Reconnaissance Module")
        print(f"{Back.BLACK}{Fore.GREEN}[*] Coming soon in the next update!")
        input(f"{Back.BLACK}{Fore.GREEN}[*] Press Enter to return to main menu...")
        
    def security_assessment_menu(self):
        """Security assessment tools submenu"""
        print(f"{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}\n🛡️ Security Assessment Tools Module")
        print(f"{Back.BLACK}{Fore.GREEN}[*] Coming soon in the next update!")
        input(f"{Back.BLACK}{Fore.GREEN}[*] Press Enter to return to main menu...")
        
    def settings_menu(self):
        """Settings and configuration submenu"""
        print(f"{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}\n⚙️ Configuration & Settings Module")
        print(f"{Back.BLACK}{Fore.GREEN}[*] Coming soon in the next update!")
        input(f"{Back.BLACK}{Fore.GREEN}[*] Press Enter to return to main menu...")
        
    def exit_application(self):
        """Exit the application gracefully"""
        self.clear_screen()
        
        exit_banner = f"""
{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  {Back.BLACK}{Fore.GREEN}{Style.BRIGHT}Thank you for using BlackDeD Ethical Hacking Toolkit!{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}        ║
║                                                                  ║
║  {Back.BLACK}{Fore.GREEN}{Style.BRIGHT}Remember: Use your skills responsibly and ethically{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}            ║
║  {Back.BLACK}{Fore.GREEN}{Style.BRIGHT}Stay updated with the latest security practices{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}                ║
║                                                                  ║
║  {Back.BLACK}{Fore.GREEN}{Style.BRIGHT}Visit our GitHub for updates and new modules{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
        print(exit_banner)
        print(f"{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}Goodbye! 👋")
        sys.exit(0)
        
    def run(self):
        """Main application loop"""
        # Show warning first
        self.display_warning()
        
        # Check dependencies first
        self.check_dependencies()
        
        # Show loading animation
        self.show_loading_animation("Initializing BlackDeD", 3)
        
        # Main loop
        while True:
            self.print_banner()
            self.show_main_menu()
            
            try:
                choice = input(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}root@blackded:~# ").strip()
                self.handle_menu_selection(choice)
            except KeyboardInterrupt:
                print(f"\n{Back.BLACK}{Fore.RED}{Style.BRIGHT}[-] Ctrl+C detected. Exiting BlackDeD...")
                self.exit_application()
            except Exception as e:
                print(f"{Back.BLACK}{Fore.RED}{Style.BRIGHT}[!] Error: {str(e)}")
                input(f"{Back.BLACK}{Fore.GREEN}[*] Press Enter to continue...")

def main():
    """Main entry point"""
    try:
        # Check if running on compatible system
        if platform.system() not in ['Linux', 'Darwin']:
            print(f"{Fore.YELLOW}{Style.BRIGHT}Warning: BlackDeD is optimized for Linux/Termux environments.")
            print(f"{Fore.YELLOW}Some features may not work correctly on {platform.system()}.")
            
        # Initialize and run BlackDeD
        app = BlackDeD()
        app.run()
        
    except Exception as e:
        print(f"{Fore.RED}{Style.BRIGHT}Critical Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()