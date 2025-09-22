#!/usr/bin/env python3
"""
Nmap XML Parser - Parses Nmap scan results and creates categorized IP lists
"""

import argparse
import xml.etree.ElementTree as ET
import sys
from pathlib import Path
import textwrap as tw
from collections import defaultdict
import os

CATEGORIES = {
    'web': {
        'ports': [80, 443, 8080, 8443],
        'services': ['http', 'https']
    },
    'windows_smb': {
        'ports': [139, 445],
        'services': ['microsoft-ds', 'netbios-ssn']
    },
    'mssql': {
        'ports': [1433],
        'services': ['ms-sql-s']
    },
    'mysql': {
        'ports': [3306],
        'services': ['mysql']
    },
    'vnc': {
        'ports': [5800, 5900],
        'services': ['vnc']
    },
    'ssh': {
        'ports': [22, 2222],
        'services': ['ssh']
    },
    'ftp': {
        'ports': [21, 2121], 
        'services': ['ftp']
    },
    'rdp': {
        'ports': [3389],
        'services': ['ms-wbt-server']
    },
    'smtp': {
        'ports': [25, 465, 587], 
        'services': ['smtp']
    },
    'dns': {
        'ports': [53], 
        'services': ['domain']
    },
    'snmp': {
        'ports': [161], 
        'services': ['snmp']
    }
}


def parse_xml(xml_path):
    """Parse Nmap XML file and extract open ports with services"""
    try:
        tree = ET.parse(xml_path)
    except FileNotFoundError:
        print(f"[!] {xml_path} file not found!")
        sys.exit(1)
    except ET.ParseError:
        print(f"[!] Error parsing {xml_path} file")
        sys.exit(1)
    
    root = tree.getroot()
    results = []
    category_ips = defaultdict(set)
    all_ips_with_ports = set()
    categorized_ips = set()
    
    for host in root.findall('host'):
        # Skip hosts that are not up
        status = host.find('status')
        if status is not None and status.get('state') != 'up':
            continue
            
        # Get IP address
        address = host.find("address[@addrtype='ipv4']")
        if address is None: 
            continue
        ip = address.get('addr')

        # Get ports 
        ports = host.find('ports')
        if ports is None:
            continue

        has_open_ports = False
        
        # Port parsing
        for port in ports.findall('port'):
            if port.find('state').get('state') != 'open':
                continue
                
            port_id = port.get('portid')
            service_elem = port.find('service')
            service_name = service_elem.get('name') if service_elem is not None else 'unknown'
            
            results.append(f"{ip} {port_id} {service_name}".strip())
            has_open_ports = True
            
            # Categorize by port and service
            for cat_name, cat_config in CATEGORIES.items():
                if (int(port_id) in cat_config['ports'] or 
                    service_name in cat_config['services']):
                    category_ips[cat_name].add(ip)
                    categorized_ips.add(ip)
        
        if has_open_ports:
            all_ips_with_ports.add(ip)
    
    other_ips = all_ips_with_ports - categorized_ips
    if other_ips:
        category_ips['other'] = other_ips
                    
    return results, category_ips, all_ips_with_ports


def setup_output_directory(output_dir):
    """Create and validate output directory"""
    path = Path(output_dir)
    
    try:
        path.mkdir(parents=True, exist_ok=True)
        
        # Test write permissions
        test_file = path / ".write_test"
        test_file.touch()
        test_file.unlink()
        
        return path
    except PermissionError:
        print(f"[!] Permission denied: cannot write to {path}. Using current directory.")
        return Path.cwd()
    except OSError as e:
        print(f"[!] Failed to create/access {path}: {e}. Using current directory.")
        return Path.cwd()
    except Exception as e:
        print(f"[!] Unexpected error with {path}: {e}. Using current directory.")
        return Path.cwd()


def save_results(results, category_ips, all_ips, output_dir):
    """Save parsing results to files"""
    output_path = setup_output_directory(output_dir)
    
    # Save all ports file
    all_ports_file = output_path / 'all_ports.txt'
    try:
        with open(all_ports_file, 'w') as f:
            f.write('\n'.join(sorted(results)))
        print(f"[+] All ports saved to: {all_ports_file}")
    except IOError as e:
        print(f"[!] Error writing to {all_ports_file}: {e}")
        return
    
    # Save all IPs file
    all_ips_file = output_path / 'all_ips.txt'
    try:
        with open(all_ips_file, 'w') as f:
            f.write('\n'.join(sorted(all_ips)))
        print(f"[+] All IPs saved to: {all_ips_file}")
    except IOError as e:
        print(f"[!] Error writing to {all_ips_file}: {e}")
    
    # Save categorized wordlists
    for cat_name, ips in category_ips.items():
        if ips:
            cat_file = output_path / f'{cat_name}.txt'
            try:
                with open(cat_file, 'w') as f:
                    f.write('\n'.join(sorted(ips)))
                print(f"[+] {cat_name}: {len(ips)} hosts saved to {cat_file}")
            except IOError as e:
                print(f"[!] Error writing to {cat_file}: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Nmap XML parser - Creates categorized IP lists from Nmap scan results",
        epilog=tw.dedent("""
            Example: 
                python3 nmap2list.py full-sweep.xml --dir ./output
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('input_file', help="Path to Nmap XML file")
    parser.add_argument('--dir', '-d', type=str, default='./lists', 
                       help='Directory to save results (default: ./lists)')
    
    args = parser.parse_args()

    # Validate input file
    if not Path(args.input_file).exists():
        print(f"[!] File '{args.input_file}' does not exist!")
        sys.exit(1)

    if not Path(args.input_file).is_file():
        print(f"[!] '{args.input_file}' is not a file!")
        sys.exit(1)

    print(f'[*] Parsing {args.input_file}')
    results, category_ips, all_ips = parse_xml(args.input_file)
    
    if not results:
        print("[!] No open ports found in the scan results!")
        sys.exit(1)
        
    print(f'[*] Found {len(results)} open ports on {len(all_ips)} unique hosts')
    print(f'[*] Saving results to {args.dir}')
    save_results(results, category_ips, all_ips, args.dir)
    
    # Print summary
    print("\n[*] Summary:")
    total_categorized = sum(len(ips) for cat_name, ips in category_ips.items() 
                           if cat_name != 'other')
    
    for cat_name, ips in sorted(category_ips.items()):
        if ips:
            percentage = (len(ips) / len(all_ips)) * 100 if all_ips else 0
            print(f"    {cat_name}: {len(ips)} hosts ({percentage:.1f}%)")
    
    print(f"[+] Done! Processed {len(all_ips)} unique hosts.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Stopped by user. Exiting...")
        sys.exit(0)