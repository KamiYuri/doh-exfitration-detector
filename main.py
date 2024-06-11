from pathlib import Path

from modifier import utils, remove_zero_flows, modify_flow_id, split_dataset

if __name__ == '__main__':
    args = utils.parse_args()

    output = Path(args.output)

    if args.bunch:
        directory = Path(args.file)
        csv_files = utils.load_csv_files(directory)

    else:
        csv_files = [Path(args.file)]

    for file in csv_files:
        data = utils.load_csv(file, nrows=args.nrows or None)

        if args.remove:
            data = remove_zero_flows.run(data, utils.gen_dataset_headers(num_bytes=args.num_bytes))

        if args.modify_flow:
            data = modify_flow_id.run(data, prefix=args.modify_flow)

        if args.split:
            if not args.train_ratio:
                raise ValueError('Train ratio is required for the split')
            else:
                train, test = split_dataset.run(data, split_ratio=args.train_ratio)

                if args.val_ratio:
                    train, val = split_dataset.run(train, split_ratio=args.val_ratio)
                    utils.save_csv(val, output / f'{file.stem}_val.csv', index=False)

                utils.save_csv(train, output / f'{file.stem}_train.csv', index=False)
        else:
            utils.save_csv(data, output, index=False)
