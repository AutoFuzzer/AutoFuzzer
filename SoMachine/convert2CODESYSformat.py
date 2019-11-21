#!/usr/bin/env python
from __future__ import print_function
import os
import argparse
import re
from collections import defaultdict

def parse_args():
    parser = argparse.ArgumentParser(
        description="convert .st file to CODESYS format"
    )
    parser.add_argument('input',
                        help="Path to the .st file. If a directory is specified, all .st files in this directory will be taken as input")
    parser.add_argument('output',
                        help='Output path to save the CODESYS-compliant .st file')
    return parser.parse_args()

def replace_operator(line, operator):
    replacement = {
            "ADD": "+",
            "SUB": "-",
            "MUL": "*",
            "DIV": "/",
            "GT": ">",
            "GE": ">=",
            "LT": "<",
            "LE": "<=",
            "EQ": "=",
            "NE": "<>",
            }
    new_line = line
    while "{}(".format(operator) in line:
        index = line.index("{}(".format(operator))
        new_line = line[:index]
        new_line += '(('
        parenthesis_level = 0
        skip_count = 0
        for i in range(index+len(operator)+1, len(line)):
            if skip_count:
                skip_count -= 1
                continue
            c = line[i]
            if parenthesis_level == 0:
                if c == '(':
                    parenthesis_level += 1
                    new_line += c
                elif c == ',':
                    new_line += ") "
                    if operator in replacement:
                        new_line += replacement[operator]
                    else:
                        new_line += operator
                    new_line += " ("
                    skip_count = 1
                elif c == ')':
                    new_line += ")"
                    new_line += line[i:]
                    break
                else:
                    new_line += c
            else:
                if c == ')':
                    parenthesis_level -= 1
                new_line += c
        line = new_line
    return line

def replace_operators(line):
    line = replace_operator(line, "AND")
    line = replace_operator(line, "XOR")
    line = replace_operator(line, "OR")
    line = replace_operator(line, "ADD")
    line = replace_operator(line, "SUB")
    line = replace_operator(line, "MUL")
    line = replace_operator(line, "DIV")
    line = replace_operator(line, "GT")
    line = replace_operator(line, "GE")
    line = replace_operator(line, "LT")
    line = replace_operator(line, "LE")
    line = replace_operator(line, "EQ")
    line = replace_operator(line, "NE")
    return line

def convert(input_file, output_file):
    # Read the original .st file
    with open(input_file) as f:
        lines = f.read().split('\n')[:-1]

    var_lines = []
    last_end_var_line_num = -1
    end_program_line_num = -1
    # Extract all var definition lines
    in_var_def = False
    for line_num, line in enumerate(lines):
        line = line.strip()
        if line.startswith("VAR"):
            if not in_var_def:
                in_var_def = True
        elif line == "END_VAR":
            if in_var_def:
                in_var_def = False
                last_end_var_index = line_num
        elif in_var_def:
            var_lines.append(line)
        elif line == "END_PROGRAM":
            end_program_line_num = line_num

    # Re-factor to conform CODESYS syntax
    # D := MOVE(EN := A, IN := B, ENO => C); IF C THEN E := D ENDIF;
    # => IF A THEN E := B ENDIF;
    # AND/OR/XOR(A, B) => A AND/OR/XOR B
    # S(1) => SET(1)
    # R(1) => RESET(1)
    skip_count = 0
    program_lines = []
    for line_num in range(last_end_var_index + 1, end_program_line_num):
        line = lines[line_num].strip()
        if len(line) == 0:
            continue
        if skip_count:
            skip_count -= 1
            continue
        if "MOVE(" in line:
            if "EN := " in line and "IN := " in line:
                EN = line.split("EN := ")[1].split(',')[0]
                IN = line.split("IN := ")[1].split(',')[0]
                program_lines.append("IF {} THEN".format(EN))
                assignee = lines[line_num + 2].strip().split(' := ')[0]
                program_lines.append("    {} := {};".format(assignee, IN))
                program_lines.append("END_IF;")
                line = replace_operators(line)
                skip_count = 3
                continue
            else:
                lhs = line.strip().split(' := ')[0]
                rhs = line.strip().split(' := ')[1].strip("MOVE();")
                program_lines.append("{} := {};".format(lhs, rhs))
                line = replace_operators(line)
                continue
        line = replace_operators(line)
        line = re.sub(r'(?<=\W)S :=', 'SET :=', line)
        line = re.sub(r'(?<=\W)R :=', 'RESET :=', line)
        line = re.sub(r'(?<=\W)S1 :=', 'SET1 :=', line)
        line = re.sub(r'(?<=\W)R1 :=', 'RESET1 :=', line)
        program_lines.append(line)

    # Save the new .st file
    with open(output_file, 'w') as f:
        f.write("PROGRAM PLC_PRG\n")
        f.write("VAR\n")
        for line in var_lines:
            f.write('  ' + line + '\n')
        f.write("END_VAR\n")
        f.write('\n')
        for line in program_lines:
            f.write(line + '\n')

if __name__ == "__main__":
    options = parse_args()
    if os.path.isdir(options.input):
        if os.path.isdir(options.output):
            for filename in os.listdir(options.input):
                input_file = os.path.join(options.input, filename)
                if not filename.endswith('.st'):
                    print("Skipping {}".format(input_file))
                    continue
                output_file = os.path.join(options.output, filename)
                convert(input_file, output_file)
        else:
            print("Error! Output must be a directory when input is a directory")
            sys.exit(-1)
    else:
        if os.path.isdir(options.output):
            _, filename = os.path.split(options.input)
            convert(options.input, os.path.join(options.output, filename))
        else:
            convert(options.input, options.output)
