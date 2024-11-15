import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import asyncio
import aiohttp
import ipaddress
import socket
import json
import time
from ipwhois import IPWhois

from AIPDBmain import aipdbmain
from IPQSmain import ipqsmain
from VTmain import vtmain
from OTXAmain import otxamain
from common import Style, timeout_set


# Function to get domain and country
async def get_domain_and_country(ip_address):
    try:
        domain = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        domain = "Unknown Domain"
        
    try:
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        country = result.get('network', {}).get('country', 'Unknown Country')
    except Exception:
        country = "Unknown Country"
    
    return domain, country

# Function to process each IP or domain (updated)
async def process_ip_or_domain(address, index, session):
    try:
        # If address is a domain, resolve it to an IP address
        if not ipaddress.ip_address(address):
            address = socket.gethostbyname(address)
    except ValueError:
        try:
            # Attempt to resolve domain
            address = socket.gethostbyname(address)
        except socket.gaierror:
            print(f"Invalid input '{address}' - Not a valid IP or domain!")
            return None

    # Get domain and country details
    domain, country = await get_domain_and_country(address)

    # AbuseIPDB
    aipdb_response_json, aipdb_status_code = await aipdbmain(f'{address}', index, session)
    if aipdb_status_code != 200:
        aipdb_response_json = {
            'data': {
                'aipdb_ip': f'{address}',
                'abuseConfidenceScore': -1,
                'isTor': f"INVALID RESULT - {aipdb_response_json['errors'][0]['detail']}"
            }}

    # VirusTotal
    vt_response_json, vt_status_code = await vtmain(f'{address}', index, session)
    vt_false_resp = {}
    if vt_status_code != 200:
        vt_false_resp = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        "NOTE": f"{vt_response_json['error']['message']} error! These results cannot be trusted!",
                        "malicious": -1,
                        "suspicious": -1,
                    }}}}
        vt_response_json.update(vt_false_resp)

    # IPQualityScore:
    ipqs_response_json = await ipqsmain(f'{address}', index, session)
    if not ipqs_response_json['success']:
        ipqs_ip = f'{address}'
        ipqs_response_json['fraud_score'] = -1
        ipqs_response_json['tor'] = ipqs_response_json['recent_abuse'] = ipqs_response_json['bot_status'] = \
            ipqs_response_json['is_crawler'] = ipqs_response_json['proxy'] = ipqs_response_json['vpn'] = \
            f"INVALID RESULTS - {ipqs_response_json['message']}"

    # OTX-AlienVault
    otxa_response_json, otxa_response_code = await otxamain(f'{address}', index, session)
    if otxa_response_code != 200:
        otxa_response_json['reputation'] = -1
        otxa_response_json['indicator'] = f"{address}"
        otxa_response_json["false_positive"] = otxa_response_json["validation"] = \
            f'INVALID RESULT - {otxa_response_json["validation"]}'

    temp = {
        'IP': address,
        'Domain': domain,
        'Country': country,
        'AbuseIPDB': {
            'abuseConfidenceScore': aipdb_response_json['data']['abuseConfidenceScore'],
            'isTor': aipdb_response_json['data']['isTor']
        },
        'VT': vt_response_json['data']['attributes']['last_analysis_stats'],
        'IPQS': {
            'fraud_score': ipqs_response_json['fraud_score'],
            'isTor': ipqs_response_json['tor'],
            'recent_abuse': ipqs_response_json['recent_abuse'],
            'bot_status': ipqs_response_json['bot_status'],
            'is_crawler': ipqs_response_json['is_crawler'],
            'proxy': ipqs_response_json['proxy'],
            'vpn': ipqs_response_json['vpn']
        },
        'OTX-A': {
            'reputation': otxa_response_json["reputation"],
            'validation': otxa_response_json["validation"],
            'FP': otxa_response_json["false_positive"]
        }
    }
    return temp


# Main asynchronous function (updated)
async def main(inputs):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_set)) as session:
        tasks = []
        for i, inp in enumerate(inputs, start=1):
            try:
                # Determine if input is IP or domain and process
                address = ipaddress.ip_address(inp)
            except ValueError:
                address = inp  # Assume it's a domain

            tasks.append(process_ip_or_domain(f'{address}', i, session))

        all_results = await asyncio.gather(*tasks)
        sorted_results = sorted(
            [result for result in all_results if result],  # Filter out None results
            key=lambda x: (
                x["VT"]["malicious"], x['AbuseIPDB']['abuseConfidenceScore'], x["VT"]["suspicious"]), reverse=True
        )
        return sorted_results


# Tkinter application class (updated)
class IPAnalysisApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP/Domain Analysis Results")
        self.root.geometry("1300x700")

        # Input Frame for IPs and Domains
        input_frame = tk.Frame(root)
        input_frame.pack(pady=10)

        # Entry to take IP addresses or domain names
        self.ip_entry = tk.Entry(input_frame, width=60)
        self.ip_entry.pack(side=tk.LEFT, padx=5)

        # Buttons to choose file or input IPs/Domains
        file_button = tk.Button(input_frame, text="Select IP/Domain File", command=self.select_file)
        file_button.pack(side=tk.LEFT, padx=5)

        load_button = tk.Button(input_frame, text="Analyze", command=self.load_data)
        load_button.pack(side=tk.LEFT, padx=5)

        # Table Setup
        columns = ("#1", "IP/Domain", "Domain Name", "Country", "AbuseIPDB Score", "VT Malicious", "IPQS Fraud Score", "OTX-A Reputation")
        self.tree = ttk.Treeview(root, columns=columns, show="headings")
        self.tree.heading("#1", text="#")
        self.tree.heading("IP/Domain", text="IP/Domain")
        self.tree.heading("Domain Name", text="Domain Name")
        self.tree.heading("Country", text="Country")
        self.tree.heading("AbuseIPDB Score", text="AbuseIPDB Score")
        self.tree.heading("VT Malicious", text="VT Malicious")
        self.tree.heading("IPQS Fraud Score", text="IPQS Fraud Score")
        self.tree.heading("OTX-A Reputation", text="OTX-A Reputation")

        for col in columns:
            self.tree.column(col, width=150)

        self.tree.pack(fill=tk.BOTH, expand=True)

    async def fetch_results(self, inputs):
        results = await main(inputs)
        return results

    def load_data(self):
        # Get IPs or domains from input box
        input_data = self.ip_entry.get()
        inputs = [ip.strip() for ip in input_data.split(',') if ip.strip()]

        if not inputs:
            messagebox.showerror("Input Error", "Please enter at least one IP or domain, or select a file.")
            return

        asyncio.run(self.display_results(inputs))

    async def display_results(self, inputs):
        results = await self.fetch_results(inputs)

        # Clear existing data in the Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Insert new data into the Treeview
        for index, result in enumerate(results, start=1):
            abuse_confidence = result['AbuseIPDB']['abuseConfidenceScore']
            vt_malicious = result['VT']['malicious']
            ipqs_fraud_score = result['IPQS']['fraud_score']
            otx_reputation = result["OTX-A"]["reputation"]
            domain_name = result.get("Domain", "N/A")
            country = result.get("Country", "N/A")

            color = self.get_color(abuse_confidence, vt_malicious, ipqs_fraud_score)

            self.tree.insert("", "end", values=(
                index, result['IP'], domain_name, country, abuse_confidence, vt_malicious, ipqs_fraud_score, otx_reputation
            ), tags=(color,))

        # Define the colors
        self.tree.tag_configure("grey", background="#e0e0e0")
        self.tree.tag_configure("red-highlighted", background="#ff4d4d", foreground="white")
        self.tree.tag_configure("orange-highlighted", background="#ffa500")
        self.tree.tag_configure("yellow-highlighted", background="#ffff66")

    def get_color(self, abuse_confidence, vt_malicious, ipqs_fraud_score):
        if abuse_confidence >= 80 or vt_malicious > 10 or ipqs_fraud_score > 80:
            return "red-highlighted"
        elif abuse_confidence >= 50 or vt_malicious >= 5 or ipqs_fraud_score >= 50:
            return "orange-highlighted"
        elif abuse_confidence >= 30 or vt_malicious >= 1 or ipqs_fraud_score >= 30:
            return "yellow-highlighted"
        else:
            return "grey"

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                inputs = [line.strip() for line in file if line.strip()]
                asyncio.run(self.display_results(inputs))


if __name__ == "__main__":
    root = tk.Tk()
    app = IPAnalysisApp(root)
    root.mainloop()
