import argparse
from pathlib import Path

import pandas as pd
from scapy.all import *
from scapy.layers.tls.all import *

import cryptography



BYTES_NUM_IN_PACKET = 512

class Label(Enum):
    BENIGN = 'benign'
    DNS2TCP = 'dns2tcp'
    IODINE = 'iodine'
    DNSCAT2 = 'dnscat2'


def run(input_dir: Path, output_path: Path, packets_num: int, label: str, flow_prefix=''):
        pcap_files = load_pcap_files(input_dir)

        print(f"Processing {len(pcap_files)} files")


        flow_index = 0
        for file in pcap_files:
            flow_packets = parse_pcap_file(file, packets_num)

            if len(flow_packets) > 0:
                flow_index += 1
                flow = [[f'{flow_prefix}{flow_index}'] + packet + [label] for packet in flow_packets] 
                
                write(flow, output_path)


def load_pcap_files(input_dir: Path) -> list:
    # Load all pcap files
    return list(input_dir.glob('*.pcap'))

def parse_pcap_file(file: Path, packets_num: int) -> list:
    print(f"Processing {file}")

    # Read the pcap file
    flow_packets = list()
    packets = rdpcap(str(Path(file).resolve()))
    for packet in packets:
        if len(flow_packets) >= packets_num:
            break
        if packet.haslayer(TLSApplicationData):
            # Extract the data from the packet
            payload_arr = extract_data(packet)
            flow_packets.append(payload_arr)

    # If the number of packets is less than the threshold, then add padding packets
    if len(flow_packets) < packets_num:
        for _ in range(packets_num - len(flow_packets)):
            flow_packets.append([0] * BYTES_NUM_IN_PACKET)

    # Increment the flow id and write the data to the output file
    return flow_packets
        
def extract_data(packet: Packet):
    tls_data = packet.getlayer(TLSApplicationData)
    hex_data = binascii.hexlify(tls_data.data).decode('utf-8')

    payload_arr = [int(hex_data[i:i + 2], 16) for i in range(0, len(hex_data), 2)]

    if len(payload_arr) < BYTES_NUM_IN_PACKET:
        # Padding the data to BYTES_NUM_IN_PACKET bytes
        payload_arr = payload_arr + [0] * (BYTES_NUM_IN_PACKET - len(payload_arr))
    else:
        # Cut the data to BYTES_NUM_IN_PACKET bytes
        payload_arr = payload_arr[:BYTES_NUM_IN_PACKET]

    return payload_arr

def write(data: list, output_path: Path):
    df = pd.DataFrame(data=data)
    df.to_csv(output_path, index=False, mode='a', header=False)


def init_output_header(output: Path):
    # Generate header
    headers = ["flow_id"]
    headers = headers + [f'byte_{i + 1}' for i in range(BYTES_NUM_IN_PACKET)]
    headers = headers + ["label"]
    df = pd.DataFrame(columns=headers)

    # Write the header to the output file
    df.to_csv(output, index=False)



if __name__ == '__main__':
    dev = False

    if dev:
        input_dir = Path.cwd().parent / 'pcaps' / 'DoHMalicious' / 'DoHMalicious' / 'test'
        output_path = Path.cwd() / 'output.csv'
        label = 'dns2tcp'
    else:
        parser = argparse.ArgumentParser(description='Parse pcap files and generate a dataset')

        parser.add_argument('-i', '--input_dir', type=str, required=True,
                            help='Input directory containing pcap files that need to be parsed')
        parser.add_argument('-o', '--output_path', type=str, required=True, help='Path of the output file')
        parser.add_argument('-n', '--packets_num', type=int, required=True, help='Number of packets per flow')
        parser.add_argument('-l', '--label', type=str, choices=['benign', 'dns2tcp', 'iodine', 'dnscat2'],
                            required=True,
                            help='Label of data')
        parser.add_argument('-f', '--flow_prefix', type=str, default='',
                            help='Prefix of the flow id (e.g., "DNS2TCP_")')

        args = parser.parse_args()

        input_dir = Path(args.input_dir)
        output_path = Path(args.output_path)
        packets_num = args.packets_num
        label = args.label
        flow_prefix = args.flow_prefix

    # Remove the existing file
    if output_path.exists():
        output_path.unlink()
    # Create the file and write the header
    output_path.touch()
    init_output_header(output_path)

    if not input_dir.exists():
        print(f"Directory '{input_dir}' does not exist")
        exit(1)

    run(input_dir=input_dir, output_path=output_path, packets_num=packets_num, label=label, flow_prefix=flow_prefix)
