#!/usr/bin/env python3
import os
import argparse

from binary import Binary

def parse_args():
    parser = argparse.ArgumentParser(
        description="Convert PLC application to disassembly"
    )
    parser.add_argument('app',
            help="Path to the application (.app) file. If a directory is given, all app files within will be analyzed")
    parser.add_argument('output',
            help="Disassembly output directory/filename")
    return parser.parse_args()

def main(app_path, output_path):
    binary = Binary(fromfile=app_path)
    disassembly = binary.disassemble()
    disassembly.save(output_path)

if __name__ == "__main__":
    options = parse_args()
    if os.path.isdir(options.app):
        for filename in sorted(os.listdir(options.app),
                key=lambda filename: int(filename.split('.')[0]) if filename.split('.')[0].isdigit() else filename.split('.')[0]):
            if not filename.endswith(".app"):
                continue
            print("Converting {}".format(filename))
            app_path = os.path.join(options.app, filename)
            output_path = os.path.join(options.output, filename.split('.')[0] + '.lst')
            main(app_path, output_path)
    else:
        if os.path.isdir(options.output):
            output_path = os.path.join(options.output, os.path.split(options.app)[-1].split('.')[0] + '.lst')
        else:
            output_path = options.output
        main(options.app, output_path)
