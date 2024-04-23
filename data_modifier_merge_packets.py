from scapy.all import *
from scapy.layers.tls.all import *
from enum import Enum

import argparse
import binascii
import glob
import json
import os
import pandas as pd

YOUR_DELAY_THRESHOLD = 40
PAYLOAD_LENGTH_THRESHOLD = 512
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

    def run(self, pcap_files_dir: str):
        # Init output file
        self.init_output()

        # Load the pcap files
        self.load_pcap_files(pcap_files_dir)
        self.read_pcap_file()

    def load_pcap_files(self, directory: str):
        # Load the pcap files
        self.pcap_list = glob.glob(os.path.join(directory, '*.pcap'))

    def read_pcap_file(self):
        # Parse the pcap files
        flow_id = 1
        for file in self.pcap_list:
            # Read the pcap file
            packets = rdpcap(file)
            if len(packets) < PACKETS_NUM_THRESHOLD:
                continue

            data_row = []
            payload_old = []
            for packet in packets:
                if packet.haslayer(TLSApplicationData):
                    # Extract the data
                    payload_new = self.extract_pcap_files(packet)
                    # If the payload length is greater than PAYLOAD_LENGTH_THRESHOLD
                    if len(payload_new) > PAYLOAD_LENGTH_THRESHOLD:
                        # If the previous payload is not empty, then append it to the payloads list
                        if payload_old:
                            data_row.append(payload_old)
                            payload_old = []

                        # Just take enough bytes to make the total length equal to PAYLOAD_LENGTH_THRESHOLD
                        data_row.append(payload_new[: PAYLOAD_LENGTH_THRESHOLD])
                    # If the payload length is less than PAYLOAD_LENGTH_THRESHOLD
                    else:
                        # Check whether new payload can be merged with the previous payload without the total length
                        # exceeding PAYLOAD_LENGTH_THRESHOLD
                        if len(payload_new) + len(payload_old) < PAYLOAD_LENGTH_THRESHOLD:
                            # Merge the new payload with the previous payload
                            payload_old.extend(payload_new)
                        # If the total length exceeds PAYLOAD_LENGTH_THRESHOLD, add old payload to the payloads list
                        else:
                            # If the previous payload is not empty, then append it to the payloads list
                            if payload_old:
                                data_row.append(payload_old)

                            payload_old = payload_new

                # Check if the number of packets is greater than or equal to 20
                if len(data_row) >= 20:
                    break

            # If the number of rows is less than 20, then skip this flow
            if len(data_row) < 20:
                continue

            # Take only the first 20 rows
            data_row = data_row[:20]

            # Add padding to the data_row
            data_row = [
                [flow_id] + item + [0] * (PAYLOAD_LENGTH_THRESHOLD - len(item)) + [self.label.value] for item in data_row]

            self.write(data_row)

            flow_id += 1

    @staticmethod
    def extract_pcap_files(packet: Packet):
        # Get the TLS data
        tls_data = packet.getlayer(TLSApplicationData)
        hex_data = binascii.hexlify(tls_data.data).decode('utf-8')

        return [int(hex_data[i:i + 2], 16) for i in range(0, len(hex_data), 2)]

    def write(self, data):
        df = pd.DataFrame(data=data,
                          columns=["flow_id"] + [f'byte_{i + 1}' for i in range(512)] + ["label"])

        if self.output_type == ModifierType.CSV:
            df.to_csv(self.output, index=False, mode='a', header=False)
        elif self.output_type == ModifierType.FEATHER:
            df.to_feather(self.output)

    def init_output(self):
        # Generate header
        headers = ["flow_id"] + [f'byte_{i + 1}' for i in range(512)] + ["label"]
        df = pd.DataFrame(columns=headers)

        if self.output_type == ModifierType.CSV:
            df.to_csv(self.output, index=False)
        elif self.output_type == ModifierType.FEATHER:
            df.to_feather(self.output)


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

    mode = ModifierType.CSV if args.mode == 'csv' else ModifierType.FEATHER

    DataModifier(output=args.output, output_type=mode, label=Label(args.label)).run(args.pcap_files_dir)

    # DataModifier(output='datasets/test_pcap/output.csv', output_type=ModifierType.CSV, label=Label.MALICIOUS,
    # custom_headers={'type': 'test', 'sasd': 'asdasd'}).run("/home/bkcs/Documents/doh/pcaps/DoHBenign-NonDoH/test")
