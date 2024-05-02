from flask import Flask,render_template,redirect,url_for,request
import content as rr
#import pandas as pd
from content import aggregation_results,extract_http_payload,extract_email_payload,extract_generic_payload,extract_pdf_payload
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import pyshark  
import subprocess
import os
from werkzeug.exceptions import BadRequest
import time
from glob import glob





app=Flask(__name__)
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/display')
def display():
    df =rr.extracted_data.to_dict('records')
    return render_template('result.html',result=df)

@app.route('/Summarization')
def Summarization():
    results=rr.aggregation_results(rr.extracted_data)
    return render_template('aggregation.html',results=results)

@app.route('/redirect')
def redirect_to_Summarization():
    return redirect(url_for('Summarization'))

@app.route('/payload_data', methods=['GET', 'POST'])
def payload_data():
    if request.method == 'POST':
        src_ip = request.form.get('src_ip')
        dest_ip = request.form.get('dest_ip')

        filtered_data = rr.extracted_data[
            (rr.extracted_data['Source IP'] == src_ip) & (rr.extracted_data['Destination IP'] == dest_ip)
        ]

        payload_data = []
        for _, row in filtered_data.iterrows():
            payload = get_payload_data(row['Protocol'], row['Info'])
            payload_data.append(payload)

        return render_template('payload_data.html', src_ip=src_ip, dest_ip=dest_ip, payload_data=payload_data)

    return render_template('enter_ip.html')




# Helper function to get payload data based on the protocol
def get_payload_data(protocol, info):
    if protocol == 'HTTP':
        pkt = pyshark.packet.Packet(raw=info)
        return extract_http_payload(pkt)
    elif protocol == 'SMTP':
        pkt = pyshark.packet.Packet(raw=info)
        return extract_email_payload(pkt)
    elif protocol == 'PDF':
        pkt = pyshark.packet.Packet(raw=info)
        return extract_pdf_payload(pkt)
    else:
        pkt = pyshark.packet.Packet(raw=info)
        return extract_generic_payload(pkt)


@app.route('/filter_protocol', methods=['POST'])
def filter_protocol():
    protocol = request.form.get('protocol')
    filtered_data = rr.extracted_data[rr.extracted_data['Protocol'].str.contains(protocol, case=False)]
    df = filtered_data.to_dict('records')
    return render_template('protocol_filter.html', result=df)

@app.route('/filter_protocol_page')
def filter_protocol_page():
    return render_template('protocol_filter.html')


@app.route('/filter_ip', methods=['POST'])
def filter_ip():
    ip_type = request.form.get('ip_type')
    ip_address = request.form.get('ip_address')
    filtered_ips = []

    if ip_type == 'source':
        filtered_ips = rr.extracted_data[rr.extracted_data['Source IP'] == ip_address]['Destination IP'].unique().tolist()
    elif ip_type == 'destination':
        filtered_ips = rr.extracted_data[rr.extracted_data['Destination IP'] == ip_address]['Source IP'].unique().tolist()
    else:
        return "Invalid IP type"

    return render_template('ip_filter.html', ip_type=ip_type, ip_address=ip_address, filtered_ips=filtered_ips)



@app.route('/filter_ip_page')
def filter_ip_page():
    return render_template('ip_filter.html')



@app.route('/ip_details')
def ip_details():
    dest_ip = request.args.get('dest_ip')
    src_ip = request.args.get('src_ip')
    details_data_src_to_dest = rr.extracted_data[
        (rr.extracted_data['Source IP'] == src_ip) & (rr.extracted_data['Destination IP'] == dest_ip)
    ]
    details_data_dest_to_src = rr.extracted_data[
        (rr.extracted_data['Source IP'] == dest_ip) & (rr.extracted_data['Destination IP'] == src_ip)
    ]

    if not details_data_src_to_dest.empty:
        details = details_data_src_to_dest.to_dict('records')
        return render_template('ip_details.html', src_ip=src_ip, dest_ip=dest_ip, details=details)
    elif not details_data_dest_to_src.empty:
        details = details_data_dest_to_src.to_dict('records')
        return render_template('ip_details.html', src_ip=dest_ip, dest_ip=src_ip, details=details)
    else:
        return "No communication data found for the selected IPs."
    
    
@app.route('/ip_details1')
def ip_details1():
    dest_ip = request.args.get('dest_ip')
    src_ip = request.args.get('src_ip')
    details_data_src_to_dest = rr.extracted_data[
        (rr.extracted_data['Source IP'] == src_ip) & (rr.extracted_data['Destination IP'] == dest_ip)
    ]
    details_data_dest_to_src = rr.extracted_data[
        (rr.extracted_data['Source IP'] == dest_ip) & (rr.extracted_data['Destination IP'] == src_ip)
    ]

    if not details_data_src_to_dest.empty:
        details = details_data_src_to_dest.to_dict('records')
        return render_template('ip_details1.html', src_ip=src_ip, dest_ip=dest_ip, details=details)
    elif not details_data_dest_to_src.empty:
        details = details_data_dest_to_src.to_dict('records')
        return render_template('ip_details1.html', src_ip=dest_ip, dest_ip=src_ip, details=details)
    else:
        return "No communication data found for the selected IPs."
    


@app.route('/filter_ips', methods=['POST'])
def filter_ips():
    src_ip = request.form.get('src_ip')
    dest_ip = request.form.get('dest_ip')
    
    filtered_data = rr.extracted_data[
        (rr.extracted_data['Source IP'] == src_ip) & (rr.extracted_data['Destination IP'] == dest_ip)
    ]
    
    protocol_counts = filtered_data['Protocol'].value_counts().reset_index()
    protocol_counts.columns = ['Protocol', 'Count']
    
    info_counts = filtered_data['Info'].value_counts().reset_index()
    info_counts.columns = ['Info', 'Count']
    custom_col=['#8a4fff']
    
    protocol_chart = BytesIO()
    plt.figure(figsize=(8, 5))
    plt.pie(protocol_counts['Count'], labels=protocol_counts['Protocol'], autopct='%1.1f%%',colors=custom_col)
    plt.title('Protocol Distribution')
    plt.savefig(protocol_chart, format='png')
    protocol_chart.seek(0)
    protocol_chart_url = base64.b64encode(protocol_chart.getvalue()).decode()

    info_chart = BytesIO()
    plt.figure(figsize=(8, 5))
    plt.pie(info_counts['Count'], labels=info_counts['Info'], autopct='%1.1f%%')
    plt.title('Data Type Distribution')
    plt.savefig(info_chart, format='png')
    info_chart.seek(0)
    info_chart_url = base64.b64encode(info_chart.getvalue()).decode()
    
    return render_template('IP_filter_both.html', src_ip=src_ip, dest_ip=dest_ip, data=filtered_data.to_dict('records'), protocol_chart_url=protocol_chart_url, info_chart_url=info_chart_url)


@app.route('/filter_both_ip')
def filter_both_ip():
    return render_template('IP_filter_both.html')

@app.route('/network_tools')
def network_tools():
    return render_template('network_tools.html')

# def read_zeek_log(log_path):
#     with open(log_path, 'r') as log_file:
#         content = log_file.read()
#     return content



@app.route('/zeek_results')
def display_logzeek():
    log_directory = '/home/deeepak/Downloads/allnewproject/Likhitha WBL/project/zeeklog_files'

    log_files = []
    for filename in os.listdir(log_directory):
        if filename.endswith('.log'):
            file_path = os.path.join(log_directory, filename)
            with open(file_path, 'r') as log_file:
                log_content = log_file.read()
                log_files.append({'filename': filename, 'content': log_content})

    return render_template('zeek_results.html', log_files=log_files)


@app.route('/suricata_results')
def display_logg():
    log_directoryy = '/home/deeepak/Downloads/allnewproject/Likhitha WBL/project/suricata_logs/'

    log_filess = []
    for filename in os.listdir(log_directoryy):
        if filename.endswith('.log'):
            file_path = os.path.join(log_directoryy, filename)
            with open(file_path, 'r') as log_file:
                log_content = log_file.read()
                log_filess.append({'filename': filename, 'content': log_content})

    return render_template('suricata_results.html', log_files=log_filess)



@app.route('/snortlog')
def display_snortlog():
    log_snortdirectory = '/home/deeepak/Downloads/allnewproject/Likhitha WBL/project/snort_logs/'

    log_files = []
    for root, _, files in os.walk(log_snortdirectory):
        for filename in files:
            file_path = os.path.join(root, filename)
            with open(file_path, 'rb') as log_file:
                try:
                    log_content = log_file.read().decode('utf-8')
                except UnicodeDecodeError:
                    # If decoding as utf-8 fails, try other encodings
                    try:
                        log_content = log_file.read().decode('latin-1')
                    except UnicodeDecodeError:
                        log_content = "Cannot decode file contents"
                log_files.append({'filename': filename, 'content': log_content})
    
    return render_template('snortlog.html', log_files=log_files)



zeek_path = '/usr/local/zeek/bin/zeek'
suricata_path = 'suricata'
suricata_outpath = '/home/deeepak/Downloads/allnewproject/Likhitha WBL/project/suricata_logs'

@app.route('/')
def index():
    return render_template('network_tools.html')




@app.route('/run_network_miner')
def runNetworkMiner():
    try:
        
        # List of commands to execute
        commands = [
            'mono /opt/NetworkMiner_2-8-1/NetworkMiner.exe',  # Example command 1
            'cdac@111'  # Example ccommand 2
        ]

        # Execute each command sequentially with a delay
        for command in commands:
            subprocess.run(command, shell=True, check=True)
            time.sleep(1)  # Delay of 1 seconds between commands
        
        return "Commands executed successfully!"
    except subprocess.CalledProcessError :
        return f"NetworkMiner Closed"

snortread = 'snort'
snortrule = '/etc/snort/snort.conf'
snort_path = '/home/deeepak/Downloads/allnewproject/Likhitha WBL/project/snort_logs/'

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        raise BadRequest('No file part')
    
    file = request.files['file']
    
    if file.filename == '':
        raise BadRequest('No file selected')
    
    if file:
        # Clear previous Zeek log files
        zeek_logs_folder = '/home/deeepak/Downloads/allnewproject/Likhitha WBL/project/zeeklog_files'
        for filename in os.listdir(zeek_logs_folder):
            file_path = os.path.join(zeek_logs_folder, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                    print(f"Deleted {filename} from {zeek_logs_folder}")
            except Exception as e:
                print(f"Error deleting {filename}: {e}")

        # Clear previous Suricata log files
        suricata_logs_folder = '/home/deeepak/Downloads/allnewproject/Likhitha WBL/project/suricata_logs'
        for filename in os.listdir(suricata_logs_folder):
            file_path = os.path.join(suricata_logs_folder, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                    print(f"Deleted {filename} from {suricata_logs_folder}")
            except Exception as e:
                print(f"Error deleting {filename}: {e}")

        snort_logs_folder = '/var/log/snort'
        for filename in os.listdir(snort_logs_folder):
            file_path = os.path.join(snort_logs_folder, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                    print(f"Deleted {filename} from {snort_logs_folder}")
            except Exception as e:
                print(f"Error deleting {filename}: {e}")        
    
    if file:
        file_path = os.path.join('/home/deeepak/Downloads/allnewproject/Likhitha WBL/project/uploads', file.filename)
        file.save(file_path)
        
        # Print file path and name to terminal
        print("File Path:", file_path)
        print("File Name:", file.filename)
        
        # Run zeek command on the uploaded file
        try:
            subprocess.run([zeek_path, '-r', file_path], check=True)
            print("Zeek command executed successfully")

            # Define the folder to move Zeek logs to
            zeek_logs_folder = '/home/deeepak/Downloads/allnewproject/Likhitha WBL/project/zeeklog_files'
            zeek_logs_path = '/home/deeepak/Downloads/allnewproject/Likhitha WBL/project/'

            # Move Zeek log files to the designated folder
            for filename in os.listdir(zeek_logs_path):
                if filename.endswith('.log'):
                    source_path = os.path.join(zeek_logs_path, filename)
                    destination_path = os.path.join(zeek_logs_folder, filename)
                    os.rename(source_path, destination_path)
                    print(f"Moved {filename} to {zeek_logs_folder}")

            try:
                subprocess.run([suricata_path, '-r',file_path, '-l', suricata_outpath ],check = True)
            except subprocess.CalledProcessError as e:
                print("Error executing suricata command", e)   

            try:
                subprocess.run([snortread,'-r', file_path, '-c', snortrule, '-l', snort_path  ],check=True)
                
            except subprocess.CalledProcessError as e:
                print("Error executing snort",e)

        except subprocess.CalledProcessError as e:
            print("Error executing zeek command:", e)
        


        return redirect(url_for('network_tools'))


@app.route('/read_snort_pcap', methods=['GET'])
def read_snort_pcap():
    # Get the latest snort log file from the directory
    log_files_pattern = '/home/deeepak/Downloads/allnewproject/Likhitha WBL/project/snort.log.*'
    log_files = glob(log_files_pattern)
    if not log_files:
        return "Error: No snort log files found"

    latest_log_file = max(log_files, key=os.path.getctime)

    # Run tcpdump command to read the latest log file
    result = subprocess.run(['tcpdump', '-r', latest_log_file], capture_output=True)

    # Check if the command executed successfully
    if result.returncode == 0:
        pcap_data = result.stdout.decode('latin-1')  # Decode using latin-1 encoding
    else:
        pcap_data = f"Error executing tcpdump command: {result.stderr.decode('utf-8')}"

    return render_template('snort_pcap.html', pcap_data=pcap_data)


if __name__ == '__main__':
    app.run(debug=True)

    
 



