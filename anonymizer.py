#!/usr/bin/env python3
import os, sys
import shutil
import argparse

def parse_args():
    parser = argparse.ArgumentParser(
            description="Anonymize the ST files and grades"
            )
    parser.add_argument('-s', '--st',
            help="Directory containing the ST files")
    parser.add_argument('-g', '--grade',
            help="Grade file")
    parser.add_argument('-d', '--dictionary', default="anonymized.csv",
            help="Name of the dictionary to anonymize the names. If not provided, a new dictionary will be created named anonymized.csv")
    return parser.parse_args()

def assert_y(response, options={"y", "Y"}, action=sys.exit):
    if response not in options:
        action()

def main(st_dir, grade_filename, dictionary_filename):
    name_index = {}
    index_name = {}
    max_index = 0
    # Attempt loading existing dictionary
    if dictionary_filename and os.path.isfile(dictionary_filename):
        try:
            with open(dictionary_filename, 'r') as f:
                for line in f:
                    name, index = line.strip().split(',')
                    index = int(index)
                    name_index[name] = index
                    index_name[index] = name
                    max_index = max(max_index, index)
            print("Loaded existing dictionary with {} entries".format(len(name_index)))
        except:
            rsp = raw_input("Error parsing anonymization dictionary file: {}. Use new dictionary? (y/N) ".format(dictionary_filename))
            assert_y(rsp)
            name_index.clear()
            index_name.clear()
            max_index = 0
    if st_dir:
        # Rename all ST files
        for filename in sorted(os.listdir(st_dir)):
            old_filepath = os.path.join(st_dir, filename)
            name, filename_extension = filename.rsplit(".", 1)
            if name not in name_index:
                max_index += 1
                name_index[name] = max_index
                index_name[max_index] = name
                print("New entry added to the dictionary: {}".format(name))
            new_filepath = os.path.join(st_dir, "{}.{}".format(name_index[name], filename_extension))
            shutil.move(old_filepath, new_filepath)
    if grade_filename:
        # Read the grades
        grades = {}
        with open(grade_filename) as f:
            f.readline()
            for line in f:
                try:
                    name, grade, comment = line.strip().split(',', 2)
                except:
                    continue
                if name not in name_index:
                    rsp = raw_input("Name {} not found in dictionary. Ignore and continue? (y/N)".format(name))
                    assert_y(rsp)
                    continue
                grades[name_index[name]] = (grade, comment)
        # Write the grades with anonymization
        with open(grade_filename, 'w') as f:
            f.write("Name,Grade,Comments\n")
            for index in sorted(grades.keys()):
                grade, comment = grades[index]
                f.write("{},{},{}\n".format(index, grade, comment))
    # Write the dictionary
    print("Saving dictionary with {} entries".format(len(name_index)))
    with open(dictionary_filename, 'w') as f:
        for index in sorted(index_name.keys()):
            f.write("{},{}\n".format(index_name[index], index))

if __name__ == "__main__":
    options = parse_args()
    main(options.st, options.grade, options.dictionary)
