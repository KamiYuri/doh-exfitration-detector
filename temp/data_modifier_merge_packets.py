import argparse
import binascii
from enum import Enum
from pathlib import Path

import pandas as pd
from scapy.all import *
from scapy.layers.tls.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

PAYLOAD_LENGTH_THRESHOLD = 512
PACKETS_NUM_THRESHOLD = 10


class ModifierType(Enum):
    CSV = 1
    FEATHER = 2


class Label(Enum):
    BENIGN = 'benign'
    DNS2TCP = 'dns2tcp'
    IODINE = 'iodine'
    DNSCAT2 = 'dnscat2'


class DataModifier:
    def __init__(self, output: Path, output_type: ModifierType, label: str):
        self.label = label
        self.output = output
        self.output_type = output_type
        self.pcaps_list = None

    def run(self, pcap_files_dir: Path):
        # Load the pcap files
        self.load_pcap_files(pcap_files_dir)
        self.read_pcap_file()

    def load_pcap_files(self, pcap_files_dir: Path):
        # Load the pcap files
        self.pcaps_list = list(pcap_files_dir.glob('*.pcap'))

    def read_pcap_file(self):
        # Parse the pcap files
        flow_id = 1
        for file in self.pcaps_list:
            print(f"Processing {file}")

            # Read the pcap file
            single_flow_packets = list()
            payload_old = list()
            packets = rdpcap(str(Path(file).resolve()))
            for packet in packets:
                if len(single_flow_packets) >= PACKETS_NUM_THRESHOLD:
                    break
                if packet.haslayer(TLSApplicationData):
                    # Extract the data
                    payload_new = self.extract_pcap_files(packet)
                    # If the payload length is greater than PAYLOAD_LENGTH_THRESHOLD
                    if len(payload_new) > PAYLOAD_LENGTH_THRESHOLD:
                        # If the previous payload is not empty, then append it to the payloads list
                        if payload_old:
                            single_flow_packets.append([flow_id] + payload_old + [self.label])
                            payload_old = list()

                        # Just take enough bytes to make the total length equal to PAYLOAD_LENGTH_THRESHOLD
                        single_flow_packets.append([flow_id] + payload_new[:PAYLOAD_LENGTH_THRESHOLD] + [self.label])
                    # If the payload length is less than PAYLOAD_LENGTH_THRESHOLD
                    else:
                        # Check whether new payload can be merged with the previous payload without the total length
                        # exceeding PAYLOAD_LENGTH_THRESHOLD
                        if len(payload_new) + len(payload_old) <= PAYLOAD_LENGTH_THRESHOLD:
                            # Merge the new payload with the previous payload
                            payload_old.extend(payload_new)
                        # If the total length exceeds PAYLOAD_LENGTH_THRESHOLD, add old payload to the payloads list
                        else:
                            # If the previous payload is not empty, then append it to the payloads list
                            if payload_old:
                                single_flow_packets.append([flow_id] + payload_old + [self.label])

                            payload_old = payload_new

            # If the number of packets is less than the threshold, then add padding packets
            if len(single_flow_packets) < PACKETS_NUM_THRESHOLD:
                for i in range(PACKETS_NUM_THRESHOLD - len(single_flow_packets)):
                    single_flow_packets.append([flow_id] + [0] * 512 + [self.label])

            flow_id += 1
            self.write(single_flow_packets)

        print(f"Total {flow_id - 1} flows")

    @staticmethod
    def extract_pcap_files(packet: Packet):
        # Get the TLS data
        tls_data = packet.getlayer(TLSApplicationData)
        hex_data = binascii.hexlify(tls_data.data).decode('utf-8')

        return [int(hex_data[i:i + 2], 16) for i in range(0, len(hex_data), 2)]

    def write(self, data):
        df = pd.DataFrame(data=data)

        if self.output_type == ModifierType.CSV:
            df.to_csv(self.output, index=False, mode='a', header=False)
        elif self.output_type == ModifierType.FEATHER:
            df.to_feather(self.output)


def init_output_header(output: Path, output_type: ModifierType):
    # Generate header
    headers = ["flow_id"]
    headers = headers + [f'byte_{i + 1}' for i in range(512)]
    headers = headers + ["label"]
    df = pd.DataFrame(columns=headers)

    # Write the header to the output file
    if output_type == ModifierType.CSV:
        df.to_csv(output, index=False)
    elif output_type == ModifierType.FEATHER:
        df.to_feather(output)


if __name__ == '__main__':
    dev = True

    if dev:
        output_path = Path('datasets/output.csv')
        input_dir = Path('datasets/pcaps')
        mode = ModifierType.CSV
        label = Label.DNS2TCP
    else:
        parser = argparse.ArgumentParser(description='Parse pcap files and generate a dataset')

        parser.add_argument('-i', '--input_dir', type=str, required=True,
                            help='Input directory containing pcap files that need to be parsed')
        parser.add_argument('-o', '--output_path', type=str, required=True, help='Path of the output file')
        parser.add_argument('-l', '--label', type=str, choices=[item.value for item in Label.__members__.values()],
                            required=True,
                            help='Flag of data: \n 0 for benign \n 1 for dns2tcp \n 2 for iodine \n 3 for dnscat2')
        parser.add_argument('-m', '--mode', type=str, choices=['csv', 'feather'], required=True,
                            help='Output mode: csv or feather')

        args = parser.parse_args()

        output_path = Path(args.output_path)
        input_dir = Path(args.input_dir)
        mode = ModifierType.CSV if args.mode == 'csv' else ModifierType.FEATHER
        label = Label(args.label)

    # Remove the existing file
    if output_path.exists():
        output_path.unlink()
    # Create the file and write the header
    output_path.touch()
    init_output_header(output_path, ModifierType.CSV)

    if not input_dir.exists():
        print(f"Directory '{input_dir}' does not exist")
        exit(1)

    DataModifier(output=output_path, output_type=mode, label=label.value).run(input_dir)

# python data_modifier_merge_packets.py --input_dir  --output_path  --label dns2tcp --mode csv
