import pyshark
import pandas as pd
from scapy.all import *
from datetime import datetime
import os




def scapyy(pcap_path):
    cap = rdpcap(pcap_path)
    info_data = []

    for i in cap:
        packet_info = i.summary()
        info_data.append(packet_info)

    return info_data

def extract_pcap_data(pcap_path):
    cap = pyshark.FileCapture(pcap_path)
    data = []
    sno = 1

    for pkt in cap:
        src_ip = pkt.ip.src if hasattr(pkt, 'ip') else ''
        dest_ip = pkt.ip.dst if hasattr(pkt, 'ip') else ''
        if hasattr(pkt, 'sniff_time'):
            timestamp = pkt.sniff_time
        else:
            timestamp = None

        src_port = ''
        dest_port = ''
        protocol = pkt.highest_layer if hasattr(pkt, 'highest_layer') else 'Unknown'

        if 'tcp' in pkt:
            src_port = pkt.tcp.srcport
            dest_port = pkt.tcp.dstport
        elif 'udp' in pkt:
            src_port = pkt.udp.srcport
            dest_port = pkt.udp.dstport
        elif 'arp' in pkt:
            src_ip = pkt.arp.src_proto_ipv4
            dest_ip = pkt.arp.dst_proto_ipv4
        length = len(pkt)

        data.append([sno, timestamp, src_ip, dest_ip, src_port, dest_port, protocol, length, ''])
        sno += 1
    cap.close()

    df = pd.DataFrame(data, columns=['S.No', 'Timestamp', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol', 'Length', 'Info'])
    return df


def aggregation_results(extracted_data):
    results = {
        'Number Of Packets': len(extracted_data),
        'Packet Shape': extracted_data.shape,
        'Source IP': extracted_data['Source IP'].nunique(),
        'Destination IP': extracted_data['Destination IP'].nunique(),
        'Unique Source Ports': extracted_data['Source Port'].nunique(),
        'Unique Destination Ports': extracted_data['Destination Port'].nunique(),
        'Protocols': extracted_data['Protocol'].value_counts().to_dict(),
        'Maximum Packet Length': extracted_data['Length'].max()
    }
    return results

def extract_email_payload(pkt):
    try:
        if pkt.smtp:
            return f'Email Content: {pkt.smtp.get_field_value("email_text")}'
    except AttributeError:
        pass
    return ''

def extract_pdf_payload(pkt):
    # We can identify PDF files based on their file signatures (magic numbers)
    pdf_magic_numbers = {'%PDF-', '%FDF-', '%PDF1.', 'PDF-', 'FDF-'}
    if hasattr(pkt, 'data') and any(magic_number in pkt.data.load for magic_number in pdf_magic_numbers):
        return 'PDF File Detected'
    return ''

def extract_http_payload(pkt):
    try:
        if pkt.http:
            # Check if it's an HTTP GET request
            if 'GET' in pkt.http.request_full_uri:
                return f'HTTP GET Request URL: {pkt.http.request_full_uri}'
            # Check if it's an HTTP POST request
            elif 'POST' in pkt.http.request_full_uri:
                return f'HTTP POST Data: {pkt.http.file_data}'
    except AttributeError:
        pass
    return ''


# Function to read packet payloads for other protocols (generic payload extraction)
def extract_generic_payload(pkt):
    if hasattr(pkt, 'data'):
        return f'Generic Payload Data: {pkt.data}'
    return ''

pcap_file_name = "project/2021-03-02-Qakbot-with-Cobalt-Strike-activity.pcap"

# Check if the file exists
if os.path.exists(pcap_file_name):
    # The file exists, so you can proceed to work with it
    pcap_path = pcap_file_name
else:
    print(f"The file {pcap_file_name} does not exist in the specified directory.")
    # You may want to handle this case, such as showing an error message or exiting the script

# Now you can proceed to work with the 'pcap_path' variable if the file exists
extracted_data = extract_pcap_data(pcap_path)  # Extract data from the PCAP file
info_data = scapyy(pcap_path)
extracted_data['Info'] = info_data
print(len(extracted_data))
print(extracted_data['Protocol'].unique())