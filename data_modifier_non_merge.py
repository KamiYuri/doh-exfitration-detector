import argparse
import json

from scapy.all import *
from scapy.layers.tls.all import *
import pyarrow.feather as feather
import pandas as pd
import os
import glob

PACKETS_NUM_THRESHOLD = 20


class ModifierType(Enum):
    CSV = 1
    FEATHER = 2


class Label(Enum):
    BENIGN = 0
    DNS2TCp = 1
    IODINE = 2
    DNSCAT2 = 3


class DataModifier:
    def __init__(self, output: str, output_type: ModifierType, label: Label):
        self.label = label
        self.output = output
        self.output_type = output_type

        self.pcap_list = None
        self.data_list = list()

    def run(self, pcap_files_dir: str):
        # Init output file
        self.init_output()

        # Load the pcap files
        self.load_pcap_files(pcap_files_dir)
        self.parse_pcap_files()

    def load_pcap_files(self, directory: str):
        # Load the pcap files
        self.pcap_list = glob.glob(os.path.join(directory, '*.pcap'))
        # self.pcap_list.sort()

    def parse_pcap_files(self):
        # Parse the pcap files
        flow_id = 1
        for file in self.pcap_list:
            pcap_data = list()
            for data in self.read_pcap_file(file, flow_id):
                # Append the data to the output file
                pcap_data.append(data)

            if len(pcap_data) >= PACKETS_NUM_THRESHOLD:
                flow_id += 1
                self.write(pcap_data[:PACKETS_NUM_THRESHOLD])

        print(f"Total {flow_id - 1} flows")

    def read_pcap_file(self, file_path: str, flow_id: int):
        single_flow_data = list()

        # Read the pcap file
        packets = rdpcap(file_path)

        packets_num = 0
        for packet in packets:
            if packets_num >= PACKETS_NUM_THRESHOLD:
                break
            if packet.haslayer(TLSApplicationData):
                # Add the flow id
                payload_arr = [flow_id]

                # Extract the data
                payload_arr = payload_arr + self.extract_data(packet)

                # Add the label
                payload_arr.append(self.label)

                single_flow_data.append(payload_arr)

                packets_num += 1

        return single_flow_data

    @staticmethod
    def extract_data(packet: Packet):
        tls_data = packet.getlayer(TLSApplicationData)
        hex_data = binascii.hexlify(tls_data.data).decode('utf-8')

        payload_arr = [int(hex_data[i:i + 2], 16) for i in range(0, len(hex_data), 2)]

        if len(payload_arr) < 512:
            # Padding the data to 512 bytes
            payload_arr = payload_arr + [0] * (512 - len(payload_arr))
        else:
            # Cut the data to 512 bytes
            payload_arr = payload_arr[:512]

        return payload_arr

    def write(self, data):
        df = pd.DataFrame(data=data,
                          columns=["flow_id"] + [f'byte_{i + 1}' for i in range(512)] + ["label"])

        if self.output_type == ModifierType.CSV:
            df.to_csv(self.output, index=False, mode='a', header=False)
        elif self.output_type == ModifierType.FEATHER:
            df.to_feather(self.output)

    def init_output(self):

        # Generate header
        headers = ["flow_id"]
        headers = headers + [f'byte_{i + 1}' for i in range(512)]
        headers = headers + ["label"]
        df = pd.DataFrame(columns=headers)

        if self.output_type == ModifierType.CSV:
            df.to_csv(self.output, index=False)
        elif self.output_type == ModifierType.FEATHER:
            df.to_feather(self.output)


# python data-modifier.py --pcap_files_dir /path/to/pcap_files --output /path/to/output_file --label 1
# --custom_headers '{"header1":"value1", "header2":"value2"}' --mode csv


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse pcap files and generate a dataset')

    parser.add_argument('-i', '--pcap_files_dir', type=str, required=True,
                        help='Input directory containing pcap files that need to be parsed')
    parser.add_argument('-o', '--output', type=str, required=True, help='Path of the output file')
    parser.add_argument('-l', '--label', type=int, choices=[item.value for item in Label.__members__.values()],
                        required=True,
                        help='Flag of data: \n 0 for benign \n 1 for dns2tcp \n 2 for iodine \n 3 for dnscat2')
    parser.add_argument('-m', '--mode', type=str, choices=['csv', 'feather'], required=True,
                        help='Output mode: csv or feather')

    args = parser.parse_args()

    # pcap_files_dir = '/home/bkcs/Documents/doh/pcaps/DoHMalicious/dns2tcp'
    # output = 'datasets/csvs/malicious/dns2tcp.csv'
    # label = Label.MALICIOUS
    # custom_headers = {"type": "dns2tcp"}

    mode = ModifierType.CSV if args.mode == 'csv' else ModifierType.FEATHER

    DataModifier(output=args.output, output_type=mode, label=args.label).run(args.pcap_files_dir)

    # Read the feather file
    # df = feather.read_feather('')
