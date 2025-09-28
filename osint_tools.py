
#!/usr/bin/env python3
"""
BlackDeD OSINT & Reconnaissance Module
Open Source Intelligence gathering and reconnaissance tools
"""

import requests
import socket
import whois
import dns.resolver
import time
import re
import json
from colorama import Fore, Back, Style
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor
import tldextract
import phonenumbers
from phonenumbers import geocoder, carrier
import qrcode
from io import BytesIO

console = Console(style="on black")

class OSINTTools:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
    
    def domain_reconnaissance(self):
        """Comprehensive domain reconnaissance"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🔍 Domain Reconnaissance")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        domain = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter domain: ").strip()
        
        if not domain:
            console.print(f"{Back.BLACK}{Fore.RED}[-] No domain provided!")
            return
        
        console.print(f"\n{Back.BLACK}{Fore.GREEN}[+] Gathering information for: {domain}")
        
        # WHOIS Information
        console.print(f"{Back.BLACK}{Fore.GREEN}[*] Performing WHOIS lookup...")
        try:
            whois_info = whois.whois(domain)
            
            whois_table = Table(show_header=False, border_style="green on black", style="on black")
            whois_table.add_column("Property", style="green on black", justify="right")
            whois_table.add_column("Value", style="bright_green on black")
            
            if whois_info.registrar:
                whois_table.add_row("Registrar", str(whois_info.registrar))
            if whois_info.creation_date:
                whois_table.add_row("Created", str(whois_info.creation_date))
            if whois_info.expiration_date:
                whois_table.add_row("Expires", str(whois_info.expiration_date))
            if whois_info.name_servers:
                whois_table.add_row("Name Servers", ", ".join(whois_info.name_servers))
            
            panel = Panel(whois_table, title="[green on black]WHOIS Information[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
            
        except Exception as e:
            console.print(f"{Back.BLACK}{Fore.YELLOW}[!] WHOIS lookup failed: {e}")
        
        # DNS Records
        console.print(f"\n{Back.BLACK}{Fore.GREEN}[*] Enumerating DNS records...")
        dns_records = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except:
                continue
        
        if dns_records:
            dns_table = Table(show_header=True, header_style="bold green on black", style="on black")
            dns_table.add_column("Record Type", style="green on black")
            dns_table.add_column("Values", style="bright_green on black")
            
            for record_type, values in dns_records.items():
                dns_table.add_row(record_type, "\n".join(values))
            
            panel = Panel(dns_table, title="[green on black]DNS Records[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
        
        # Subdomain enumeration
        console.print(f"\n{Back.BLACK}{Fore.GREEN}[*] Enumerating subdomains...")
        subdomains = self.enumerate_subdomains(domain)
        
        if subdomains:
            subdomain_table = Table(show_header=True, header_style="bold green on black", style="on black")
            subdomain_table.add_column("Subdomain", style="green on black")
            subdomain_table.add_column("IP Address", style="bright_green on black")
            subdomain_table.add_column("Status", style="white on black")
            
            for subdomain, ip, status in subdomains:
                subdomain_table.add_row(subdomain, ip, status)
            
            panel = Panel(subdomain_table, title=f"[green on black]Subdomains Found ({len(subdomains)})[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
    
    def enumerate_subdomains(self, domain):
        """Enumerate subdomains using common wordlist"""
        subdomains_list = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'app', 'blog', 'shop', 'store', 'support', 'help', 'docs',
            'cdn', 'assets', 'static', 'img', 'images', 'video', 'videos',
            'secure', 'ssl', 'vpn', 'remote', 'portal', 'dashboard',
            'panel', 'cpanel', 'phpmyadmin', 'webmail', 'mx', 'ns1', 'ns2'
        ]
        
        found_subdomains = []
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                # Check if it's accessible
                try:
                    response = self.session.get(f"http://{full_domain}", timeout=3)
                    status = f"HTTP {response.status_code}"
                except:
                    status = "Resolved"
                return (full_domain, ip, status)
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in subdomains_list]
            
            for future in futures:
                result = future.result()
                if result:
                    found_subdomains.append(result)
        
        return found_subdomains
    
    def email_harvester(self):
        """Harvest email addresses from websites"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}📧 Email Harvester")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        target = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter domain or URL: ").strip()
        
        if not target:
            console.print(f"{Back.BLACK}{Fore.RED}[-] No target provided!")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        console.print(f"{Back.BLACK}{Fore.GREEN}[+] Harvesting emails from: {target}")
        
        emails = set()
        
        try:
            # Get main page
            response = self.session.get(target, timeout=10)
            
            # Email regex pattern
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            
            # Find emails in main page
            found_emails = re.findall(email_pattern, response.text)
            emails.update(found_emails)
            
            # Look for additional pages
            link_pattern = r'href=[\'"]?([^\'" >]+)'
            links = re.findall(link_pattern, response.text)
            
            # Check common pages for emails
            common_pages = ['/contact', '/about', '/team', '/staff', '/support']
            
            for page in common_pages:
                try:
                    page_url = target.rstrip('/') + page
                    page_response = self.session.get(page_url, timeout=5)
                    page_emails = re.findall(email_pattern, page_response.text)
                    emails.update(page_emails)
                except:
                    continue
            
            # Display results
            if emails:
                email_table = Table(show_header=True, header_style="bold green on black", style="on black")
                email_table.add_column("Email Address", style="bright_green on black")
                email_table.add_column("Domain", style="green on black")
                
                for email in sorted(emails):
                    domain = email.split('@')[1] if '@' in email else 'Unknown'
                    email_table.add_row(email, domain)
                
                panel = Panel(email_table, title=f"[green on black]Harvested Emails ({len(emails)} found)[/green on black]", border_style="green on black", style="on black")
                console.print(panel)
            else:
                console.print(f"{Back.BLACK}{Fore.YELLOW}[!] No email addresses found")
                
        except Exception as e:
            console.print(f"{Back.BLACK}{Fore.RED}[-] Email harvesting failed: {e}")
    
    def phone_number_lookup(self):
        """Phone number OSINT lookup"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}📱 Phone Number Lookup")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        phone_input = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter phone number (with country code): ").strip()
        
        if not phone_input:
            console.print(f"{Back.BLACK}{Fore.RED}[-] No phone number provided!")
            return
        
        try:
            # Parse phone number
            parsed_number = phonenumbers.parse(phone_input, None)
            
            # Validate number
            if not phonenumbers.is_valid_number(parsed_number):
                console.print(f"{Back.BLACK}{Fore.RED}[-] Invalid phone number!")
                return
            
            # Get information
            country = geocoder.description_for_number(parsed_number, "en")
            carrier_name = carrier.name_for_number(parsed_number, "en")
            number_type = phonenumbers.number_type(parsed_number)
            
            # Format number
            formatted_international = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            formatted_national = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)
            formatted_e164 = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
            
            # Number type mapping
            type_mapping = {
                phonenumbers.PhoneNumberType.MOBILE: "Mobile",
                phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
                phonenumbers.PhoneNumberType.VOIP: "VoIP",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free"
            }
            
            phone_table = Table(show_header=False, border_style="green on black", style="on black")
            phone_table.add_column("Property", style="green on black", justify="right")
            phone_table.add_column("Value", style="bright_green on black")
            
            phone_table.add_row("Input Number", phone_input)
            phone_table.add_row("International", formatted_international)
            phone_table.add_row("National", formatted_national)
            phone_table.add_row("E164", formatted_e164)
            phone_table.add_row("Country", country if country else "Unknown")
            phone_table.add_row("Carrier", carrier_name if carrier_name else "Unknown")
            phone_table.add_row("Type", type_mapping.get(number_type, "Unknown"))
            phone_table.add_row("Country Code", f"+{parsed_number.country_code}")
            phone_table.add_row("Valid", "Yes" if phonenumbers.is_valid_number(parsed_number) else "No")
            
            panel = Panel(phone_table, title="[green on black]Phone Number Information[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
            
        except phonenumbers.NumberParseException as e:
            console.print(f"{Back.BLACK}{Fore.RED}[-] Phone number parsing failed: {e}")
        except Exception as e:
            console.print(f"{Back.BLACK}{Fore.RED}[-] Phone lookup failed: {e}")
    
    def qr_code_generator(self):
        """Generate QR codes for OSINT data"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}📱 QR Code Generator")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        data = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter data for QR code: ").strip()
        
        if not data:
            console.print(f"{Back.BLACK}{Fore.RED}[-] No data provided!")
            return
        
        try:
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            # Create image
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Save to file
            filename = f"qrcode_{int(time.time())}.png"
            img.save(filename)
            
            console.print(f"\n{Back.BLACK}{Fore.GREEN}[+] QR code generated successfully!")
            console.print(f"{Back.BLACK}{Fore.GREEN}[+] Saved as: {filename}")
            console.print(f"{Back.BLACK}{Fore.GREEN}[+] Data: {data}")
            
            # Display QR info
            qr_table = Table(show_header=False, border_style="green on black", style="on black")
            qr_table.add_column("Property", style="green on black", justify="right")
            qr_table.add_column("Value", style="bright_green on black")
            
            qr_table.add_row("Data", data)
            qr_table.add_row("Filename", filename)
            qr_table.add_row("Size", f"{img.size[0]}x{img.size[1]} pixels")
            qr_table.add_row("Error Correction", "Low (7%)")
            
            panel = Panel(qr_table, title="[green on black]QR Code Information[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
            
        except Exception as e:
            console.print(f"{Back.BLACK}{Fore.RED}[-] QR code generation failed: {e}")
    
    def ip_geolocation(self):
        """IP address geolocation lookup"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🌍 IP Geolocation Lookup")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        ip_address = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter IP address: ").strip()
        
        if not ip_address:
            console.print(f"{Back.BLACK}{Fore.RED}[-] No IP address provided!")
            return
        
        try:
            # Use free IP geolocation API
            response = self.session.get(f"http://ip-api.com/json/{ip_address}", timeout=10)
            data = response.json()
            
            if data['status'] == 'success':
                geo_table = Table(show_header=False, border_style="green on black", style="on black")
                geo_table.add_column("Property", style="green on black", justify="right")
                geo_table.add_column("Value", style="bright_green on black")
                
                geo_table.add_row("IP Address", data.get('query', 'N/A'))
                geo_table.add_row("Country", data.get('country', 'N/A'))
                geo_table.add_row("Country Code", data.get('countryCode', 'N/A'))
                geo_table.add_row("Region", data.get('regionName', 'N/A'))
                geo_table.add_row("City", data.get('city', 'N/A'))
                geo_table.add_row("ZIP Code", data.get('zip', 'N/A'))
                geo_table.add_row("Latitude", str(data.get('lat', 'N/A')))
                geo_table.add_row("Longitude", str(data.get('lon', 'N/A')))
                geo_table.add_row("Timezone", data.get('timezone', 'N/A'))
                geo_table.add_row("ISP", data.get('isp', 'N/A'))
                geo_table.add_row("Organization", data.get('org', 'N/A'))
                geo_table.add_row("AS Number", data.get('as', 'N/A'))
                
                panel = Panel(geo_table, title="[green on black]IP Geolocation Information[/green on black]", border_style="green on black", style="on black")
                console.print(panel)
            else:
                console.print(f"{Back.BLACK}{Fore.RED}[-] Geolocation lookup failed: {data.get('message', 'Unknown error')}")
                
        except Exception as e:
            console.print(f"{Back.BLACK}{Fore.RED}[-] Geolocation lookup failed: {e}")
    
    def show_menu(self):
        """Display OSINT tools menu"""
        while True:
            console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🔍 OSINT & RECONNAISSANCE MODULE")
            console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 50)
            
            options = [
                ("1", "🌐 Domain Reconnaissance", "WHOIS, DNS, subdomain enumeration"),
                ("2", "📧 Email Harvester", "Extract emails from websites"),
                ("3", "📱 Phone Number Lookup", "Phone number OSINT analysis"),
                ("4", "🌍 IP Geolocation", "IP address location lookup"),
                ("5", "📱 QR Code Generator", "Generate QR codes for data"),
                ("6", "🔍 Social Media Search", "Search across social platforms"),
                ("0", "🔙 Back to Main Menu", "Return to BlackDeD main menu")
            ]
            
            menu_table = Table(show_header=True, header_style="bold green on black", style="on black")
            menu_table.add_column("Option", style="green on black", justify="center", width=8)
            menu_table.add_column("Tool", style="bright_green on black", width=25)
            menu_table.add_column("Description", style="white on black", width=40)
            
            for option, tool, description in options:
                menu_table.add_row(option, tool, description)
            
            panel = Panel(menu_table, title="[green on black]OSINT & Reconnaissance Tools[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
            
            try:
                choice = input(f"\n{Back.BLACK}{Fore.GREEN}root@blackded:~# Select option: ").strip()
                
                if choice == "1":
                    self.domain_reconnaissance()
                elif choice == "2":
                    self.email_harvester()
                elif choice == "3":
                    self.phone_number_lookup()
                elif choice == "4":
                    self.ip_geolocation()
                elif choice == "5":
                    self.qr_code_generator()
                elif choice == "6":
                    console.print(f"{Back.BLACK}{Fore.GREEN}[*] Social media search coming in next update!")
                elif choice == "0":
                    break
                else:
                    console.print(f"{Back.BLACK}{Fore.RED}[-] Invalid option!")
                
                if choice != "0":
                    input(f"\n{Back.BLACK}{Fore.GREEN}[*] Press Enter to continue...")
                    
            except KeyboardInterrupt:
                console.print(f"\n{Back.BLACK}{Fore.YELLOW}[!] Returning to main menu...")
                break

def main():
    osint = OSINTTools()
    osint.show_menu()

if __name__ == "__main__":
    main()
