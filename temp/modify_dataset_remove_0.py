import argparse
from pathlib import Path

import dask.dataframe as df

parser = argparse.ArgumentParser(description='Parse pcap files and generate a dataset')
parser.add_argument('-f', '--file', type=str, required=True, help='Path of the input file')
# parser.add_argument('-o', '--output', type=str, required=True, help='Path of the output file')

args = parser.parse_args()

path = Path(args.file)
output = Path.cwd() / 'dataset' / path.name


dataframe = df.read_csv(path).compute()
columns_to_check = [col for col in dataframe.columns if col.startswith('byte_')]

# Get the list of column names that start with 'byte_'
# Group the DataFrame by 'flow_id' and filter
dataframe = dataframe.groupby('flow_id').filter(lambda x: not (x[columns_to_check] == 0).all().all())
# Save the shuffled dataset to a new file

dataframe.to_csv(output, index=False)
