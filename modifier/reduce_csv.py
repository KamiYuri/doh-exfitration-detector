import pandas as pd
import argparse
from pathlib import Path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Reduce the size of the dataset')

    parser.add_argument('--input', type=str, help='The path to the input dataset')
    parser.add_argument('--output', type=str, help='The path to the output dataset')

    args = parser.parse_args()

    csv_file = Path(args.input)
    output_file = Path(args.output)

    df = pd.read_csv(csv_file).head(200000)
    df.to_csv(output_file, index=False)