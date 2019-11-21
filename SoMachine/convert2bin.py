# encoding:utf-8
from __future__ import print_function
import os, sys
import argparse
import traceback

def parse_args():
    parser = argparse.ArgumentParser(
        description="convert SoMachine project to binary file"
    )
    parser.add_argument('project',
                        help="Path to the SoMachine .project file")
    parser.add_argument('output',
                        help='Output directory to save the .bin file')
    return parser.parse_args()

def saveBin(project_file, output_dir):
    if projects.primary:
        projects.primary.close()
    # open project
    proj = projects.open(project_file)

    app = proj.active_application
    output_path = os.path.join(output_dir, os.path.split(project_file)[-1].replace(".project", ".app"))
    app.create_boot_application(output_path)

if __name__ == "__main__":
    options = parse_args()
    if os.path.isdir(options.project):
        failed_conversions = set()
        for filename in os.listdir(options.project):
            if filename.endswith(".project"):
                project_file = os.path.join(options.project, filename)
                print("Converting {}...".format(project_file))
                try:
                    saveBin(project_file, options.output)
                except:
                    print("Error encountered!")
                    failed_conversions.add(filename)
        if len(failed_conversions):
            print("Failed conversions:")
            for conversion in sorted(failed_conversions):
                print(conversion)
        else:
            print("All success!")
    else:
        saveBin(options.project, options.output)
