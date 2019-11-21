# encoding:utf-8
from __future__ import print_function
import os, sys
import argparse
import traceback

def parse_args():
    parser = argparse.ArgumentParser(
        description="convert .st file to SoMachine project"
    )
    parser.add_argument('template',
                        help="Path to the template SoMachine .project file")
    parser.add_argument('st_file',
                        help="Path to the .st file. If a directory is specified, all .st files in this directory will be taken as input")
    parser.add_argument('output',
                        help='Output directory to save the SoMachine project and other files')
    return parser.parse_args()

def saveSoMachine(template, st_file, output_dir):
    if projects.primary:
        projects.primary.close()
    # open project
    proj = projects.open(template)

    # Find device object
    devices = proj.find('MyController',True)
    if devices:
        if len(devices) == 1:
            device = devices[0]
        else:
            print("More than one devices found")
            return
    else:
        print("No device found")
        return

    # Find the PLC Logic object
    plc_prg = device.find("PLC_PRG", True)[1]

    is_var = False
    var_lines = []
    program_lines = []
    with open(st_file) as f:
        for line in f:
            if len(line.strip()) == 0:
                continue
            if line.startswith("PROGRAM "):
                is_var = True
            if is_var:
                var_lines.append(line)
            else:
                program_lines.append(line)
            if line.startswith("END_VAR"):
                is_var = False
    plc_prg.set_interface_text("".join(var_lines))
    plc_prg.set_implementation_text("".join(program_lines))

    # Clear all messages
    message_categories = system.get_message_categories()
    for category in message_categories:
        system.clear_messages(category)

    # Compile the project
    app = proj.active_application
    app.build()

    # Retrieve build message only
    message_categories = system.get_message_categories()
    build_category = None
    for category in message_categories:
        description = system.get_message_category_description(category)
        if description == "Build":
            build_category = category
    message = system.get_messages(build_category)

    if "Compile complete -- 0 errors, 0 warnings" in message:
        print("Compiled successfully!")

        # Save the project
        output_path = os.path.join(output_dir, os.path.split(st_file)[-1].replace(".st", ".project"))
        proj.save_as(output_path)
        print("Saved as {}".format(output_path))
        return True
    else:
        print("Error!")
        return False

if __name__ == "__main__":
    options = parse_args()
    if os.path.isdir(options.st_file):
        failed_conversions = set()
        for filename in os.listdir(options.st_file):
            if filename.endswith(".st"):
                st_file = os.path.join(options.st_file, filename)
                print("Converting {}...".format(st_file))
                if not saveSoMachine(options.template, st_file, options.output):
                    failed_conversions.add(filename)
        if len(failed_conversions):
            print("Failed conversions:")
            for conversion in sorted(failed_conversions):
                print(conversion)
        else:
            print("All success!")
    else:
        saveSoMachine(options.template, options.st_file, options.output)
