#!/data/data/com.termux/files/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import requests
import json
import socket
import dns.resolver
from datetime import datetime
from bs4 import BeautifulSoup
import concurrent.futures
import argparse

class OSINTRecon:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.results = {
            'target': target,
            'timestamp': str(datetime.now()),
            'dns': {},
            'web': {},
            'social': {},
            'metadata': {}
        }
    
    def banner(self):
        print("\033[92m" + "="*60)
        print("    kArmas_OSINT Enhanced Python Module")
        print("    Advanced Web Scraping & API Integration")
        print("="*60 + "\033[0m\n")
    
    def dns_recon(self):
        print("\033[93m[+] Enhanced DNS Reconnaissance\033[0m")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                self.results['dns'][record_type] = [str(rdata) for rdata in answers]
                print(f"  [✓] {record_type}: {len(answers)} records")
            except:
                pass
    
    def web_scraping(self):
        print("\033[93m[+] Advanced Web Scraping\033[0m")
        
        try:
            response = requests.get(f"http://{self.target}", timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract metadata
            self.results['web']['title'] = soup.title.string if soup.title else "N/A"
            self.results['web']['meta_description'] = ""
            
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                self.results['web']['meta_description'] = meta_desc.get('content', '')
            
            # Extract links
            links = [a.get('href') for a in soup.find_all('a', href=True)]
            self.results['web']['links_count'] = len(links)
            self.results['web']['external_links'] = [l for l in links if 'http' in str(l) and self.target not in str(l)]
            
            # Extract social media links
            social_platforms = ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'youtube.com']
            social_links = {}
            
            for link in links:
                for platform in social_platforms:
                    if platform in str(link):
                        platform_name = platform.split('.')[0]
                        social_links[platform_name] = link
            
            self.results['social'] = social_links
            
            print(f"  [✓] Title: {self.results['web']['title']}")
            print(f"  [✓] Links found: {self.results['web']['links_count']}")
            print(f"  [✓] Social profiles: {len(social_links)}")
            
        except Exception as e:
            print(f"  [!] Web scraping error: {e}")
    
    def reverse_ip(self):
        print("\033[93m[+] Reverse IP Lookup\033[0m")
        
        try:
            ip = socket.gethostbyname(self.target)
            self.results['dns']['ip_address'] = ip
            print(f"  [✓] IP Address: {ip}")
            
            # Reverse lookup
            try:
                hostname = socket.gethostbyaddr(ip)
                self.results['dns']['ptr_record'] = hostname[0]
                print(f"  [✓] PTR Record: {hostname[0]}")
            except:
                pass
                
        except Exception as e:
            print(f"  [!] Reverse IP error: {e}")
    
    def http_security_headers(self):
        print("\033[93m[+] HTTP Security Headers Analysis\033[0m")
        
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
        
        try:
            response = requests.get(f"https://{self.target}", timeout=10, verify=False)
            headers_found = {}
            
            for header in security_headers:
                if header in response.headers:
                    headers_found[header] = response.headers[header]
                    print(f"  [✓] {header}: Present")
                else:
                    print(f"  [!] {header}: Missing")
            
            self.results['web']['security_headers'] = headers_found
            
        except Exception as e:
            print(f"  [!] Security headers check error: {e}")
    
    def technology_detection(self):
        print("\033[93m[+] Technology Stack Detection\033[0m")
        
        try:
            response = requests.get(f"http://{self.target}", timeout=10)
            
            technologies = []
            
            # Check response headers
            if 'Server' in response.headers:
                technologies.append(f"Server: {response.headers['Server']}")
            
            if 'X-Powered-By' in response.headers:
                technologies.append(f"Powered-By: {response.headers['X-Powered-By']}")
            
            # Check HTML content
            content = response.text.lower()
            
            tech_signatures = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Joomla': ['joomla', 'option=com_'],
                'Drupal': ['drupal', '/sites/default/'],
                'React': ['react', '__react'],
                'Angular': ['ng-app', 'angular'],
                'Vue.js': ['vue', 'v-'],
                'jQuery': ['jquery'],
                'Bootstrap': ['bootstrap']
            }
            
            for tech, signatures in tech_signatures.items():
                if any(sig in content for sig in signatures):
                    technologies.append(tech)
                    print(f"  [✓] Detected: {tech}")
            
            self.results['web']['technologies'] = technologies
            
        except Exception as e:
            print(f"  [!] Technology detection error: {e}")
    
    def save_results(self):
        print("\n\033[93m[+] Saving Results\033[0m")
        
        output_file = f"{self.output_dir}/enhanced_results.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        print(f"  [✓] Results saved to: {output_file}")
        
        # Create human-readable report
        report_file = f"{self.output_dir}/enhanced_report.txt"
        
        with open(report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("kArmas_OSINT Enhanced Report\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Timestamp: {self.results['timestamp']}\n")
            f.write("="*60 + "\n\n")
            
            f.write("DNS Information:\n")
            f.write("-"*40 + "\n")
            for key, value in self.results['dns'].items():
                f.write(f"{key}: {value}\n")
            
            f.write("\nWeb Information:\n")
            f.write("-"*40 + "\n")
            for key, value in self.results['web'].items():
                f.write(f"{key}: {value}\n")
            
            f.write("\nSocial Media Profiles:\n")
            f.write("-"*40 + "\n")
            for platform, url in self.results['social'].items():
                f.write(f"{platform}: {url}\n")
        
        print(f"  [✓] Report saved to: {report_file}")
    
    def run(self):
        self.banner()
        self.dns_recon()
        self.reverse_ip()
        self.web_scraping()
        self.http_security_headers()
        self.technology_detection()
        self.save_results()
        
        print("\n\033[92m" + "="*60)
        print("    [✓] Enhanced reconnaissance complete!")
        print("="*60 + "\033[0m")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='kArmas_OSINT Enhanced Module')
    parser.add_argument('target', help='Target domain')
    parser.add_argument('-o', '--output', default='osint_enhanced', help='Output directory')
    
    args = parser.parse_args()
    
    import os
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    
    recon = OSINTRecon(args.target, args.output)
    recon.run()
