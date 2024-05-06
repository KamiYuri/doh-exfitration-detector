import argparse
from pathlib import Path

import dask.dataframe as dd

parser = argparse.ArgumentParser(description='Parse pcap files and generate a dataset')
parser.add_argument('-p', '--prefix', type=str, required=True, help='Prefix of the flow_id')
parser.add_argument('-f', '--file', type=str, required=True, help='Path of the input file')
parser.add_argument('-o', '--output', type=str, required=True, help='Path of the output file')

args = parser.parse_args()

path = Path(args.file)

df = dd.read_csv(path).repartition(npartitions=1)

df = df.assign(flow_id=args.prefix + df['flow_id'].astype(str)).persist()

df.to_csv(args.output, index=False, single_file=True)
