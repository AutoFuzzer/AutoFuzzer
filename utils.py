#!/usr/bin/env python3
import os
import shutil
import gc

from dtype import *
from automaton import Automaton

def dispose_st(st_dir, disposal_dir, grades_path):
    with open(grades_path) as f:
        # Ignore header line
        f.readline()
        for line in f:
            try:
                name, grade, comment = line.strip().split(',', 2)
                comment = comment.replace(',', '')
                if len(comment) > 0:
                    # Move to disposal
                    src_path = os.path.join(st_dir, "{}.st".format(name))
                    if os.path.isfile(src_path):
                        dst_path = os.path.join(disposal_dir, "{}.st".format(name))
                        shutil.move(src_path, dst_path)
                    else:
                        print("No file found: {}".format(name))
            except:
                continue

def convert_graph(filename, input_len):
    lines = []
    edgedef = False
    with open(filename) as in_f:
        with open(filename + '~', 'w') as out_f:
            for line in in_f:
                if edgedef:
                    line = line.replace("Timers: ", "")
                    line = line.replace("Counters: ", "")
                    position = line.index("Input: ")
                    input_val = Value(int(line[position+7:position+17], 0))
                    inputs = SortedInput()
                    mask = Value(0xFF)
                    for index in range(input_len):
                        inputs[index] = input_val & mask
                        input_val >>= 8
                    if input_val != 0:
                        raise ValueError("Input overflow")
                    line = line[:position] + str(inputs) + line[position+17:]
                    out_f.write(line)
                elif line.startswith("edgedef>"):
                    edgedef = True
                    out_f.write(line)
                else:
                    out_f.write(line)
    shutil.move(filename + '~', filename)

def batch_convert_graph(directory, input_len):
    for filename in os.listdir(directory):
        if not filename.endswith(".gdf"):
            continue
        print("Converting {}".format(filename))
        filepath = os.path.join(directory, filename)
        convert_graph(filepath, input_len)

def convert_graph_fmt(filename, fmt, output_dir=None):
    automaton = Automaton(fromfile=filename)
    filename_dir, filename_name = os.path.split(filename)
    if output_dir:
        filename_dir = output_dir
    new_filename = os.path.join(filename_dir, ".".join([filename_name.split('.')[0], fmt]))
    automaton.export(filename=new_filename)

def batch_convert_graph_fmt(directory, fmt, output_dir=None, force_gc=False):
    for filename in os.listdir(directory):
        if force_gc:
            if not gc.isenabled():
                print("Enabling GC")
                gc.enable()
            print("Collecting garbage")
            n = gc.collect()
            print("{} objects collected".format(n))
        print("Converting {}".format(filename))
        filepath = os.path.join(directory, filename)
        convert_graph_fmt(filepath, fmt, output_dir=output_dir)

def verify_convert_graph_fmt(filename1, filename2):
    a1 = Automaton(fromfile=filename1)
    a2 = Automaton(fromfile=filename2)
    if a1 != a2:
        print("Automaton {} and {} differ".format(filename1, filename2))

def batch_verify_convert_graph_fmt(dir1, dir2):
    dir1_files = {filename.rsplit('.', 1)[0]: filename for filename in os.listdir(dir1)}
    dir2_files = {filename.rsplit('.', 1)[0]: filename for filename in os.listdir(dir2)}
    for filename_base, filename in dir1_files.items():
        if filename_base not in dir2_files.keys():
            print("{} Only in {}".format(filename_base, dir1))
        else:
            verify_convert_graph_fmt(
                    os.path.join(dir1, filename),
                    os.path.join(dir2, dir2_files[filename_base])
                    )
    for filename_base, filename in dir2_files.items():
        if filename_base not in dir1_files.keys():
            print("{} Only in {}".format(filename_base, dir2))

def move_err_log(src, dst):
    for filename in os.listdir(src):
        if filename.endswith(".log"):
            src_file = os.path.join(src, filename)
            dst_file = os.path.join(dst, filename)
            shutil.move(src_file, dst_file)
            print("Moved {}".format(filename))
