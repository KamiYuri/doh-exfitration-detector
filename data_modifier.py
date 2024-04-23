import argparse
from pathlib import Path

import pandas as pd
from scapy.all import *
from scapy.layers.tls.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

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
        self.pcaps_list = list()
        self.data_list = list()

    def run(self, pcap_files_dir: Path):
        self.load_pcap_files(pcap_files_dir)
        self.parse_pcap_files()

    def load_pcap_files(self, pcap_files_dir: Path):
        # Load all pcap files
        self.pcaps_list.extend(pcap_files_dir.glob('*.pcap'))

    def parse_pcap_files(self):
        # Parse the pcap files
        flow_id = 1
        for file in self.pcaps_list:
            print(f"Processing {file}")

            # Read the pcap file
            single_flow_packets = list()
            packets = rdpcap(str(Path(file).resolve()))
            for packet in packets:
                if len(single_flow_packets) >= PACKETS_NUM_THRESHOLD:
                    break
                if packet.haslayer(TLSApplicationData):
                    # Extract the data from the packet
                    payload_arr = [flow_id] + self.extract_data(packet) + [self.label]
                    single_flow_packets.append(payload_arr)

            # If the number of packets is less than the threshold, then add padding packets
            if len(single_flow_packets) < PACKETS_NUM_THRESHOLD:
                for i in range(PACKETS_NUM_THRESHOLD - len(single_flow_packets)):
                    single_flow_packets.append([flow_id] + [0] * 512 + [self.label])

            # Increment the flow id and write the data to the output file
            flow_id += 1
            self.write(single_flow_packets)

        print(f"Total {flow_id - 1} flows")

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

    def write(self, data: list):
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
    dev = False

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

# python data_modifier.py --input_dir  --output_path  --label dns2tcp --mode csv
