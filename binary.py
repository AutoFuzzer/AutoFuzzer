#!/usr/bin/env python3
import os
import shutil
from itertools import combinations

from capstone import *

from dtype import *
from disassembly import *

class Binary(object):
    def __init__(self, binary=None, fromfile=None):
        self.__binary__ = binary
        if fromfile:
            self.fromfile(fromfile)

    def get(self):
        return self.__binary__

    def fromfile(self, filename):
        with open(filename, 'rb') as f:
            self.__binary__ = f.read()

    def clear(self, positions):
        temp_binary = [c for c in self.__binary__]
        for position in positions:
            temp_binary[position] = '\x00'
        self.__binary__ = temp_binary

    def set(self, positions):
        temp_binary = [c for c in self.__binary__]
        for position in positions:
            temp_binary[position] = '\xff'
        self.__binary__ = temp_binary

    def save(self, filename):
        with open(filename, 'wb') as f:
            f.write(self.__binary__)

    def disassemble(self, log=False):
        # Assuming ARM-32 (non-THUMB)
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        addr_acc = 0
        disassembly = Disassembly()
        state = Decoded
        while addr_acc < len(self.__binary__):
            temp_acc = 0
            for i in md.disasm(self.__binary__[addr_acc:], addr_acc):
                addr = Address(i.address)
                if state == Decoded:
                    if i.mnemonic == "push" and i.op_str == "{sl, lr}":
                        state = Instruction
                    else:
                        decoded = Decoded(i.bytes)
                        disassembly[addr] = decoded
                        if log:
                            print("{}: {}:\t{}".format("data", addr, decoded))
                        temp_acc += i.size
                        continue
                elif state == Instruction:
                    if i.mnemonic == "pop" and i.op_str == "{sl, pc}":
                        state = Decoded
                instruction = Instruction(i.bytes, i.mnemonic, i.op_str)
                disassembly[addr] = instruction
                temp_acc += i.size
                if log:
                    print("{}: {}:\t{}".format("code", addr, instruction))
            addr_acc += temp_acc
            if addr_acc < len(self.__binary__):
                # Encountered a broken instruction
                addr = Address(addr_acc)
                b = bytearray(self.__binary__[addr_acc:addr_acc+4])
                decoded = Decoded(b)
                disassembly[addr] = decoded
                if log:
                    print("{}: {}:\t{}".format("data", addr, decoded))
                addr_acc += 4
        # Scan all the code section to find all incorrectly disassembled code
        # section and convert back to data section
        code_coverage = set()
        conditional_branches_remaining = set()
        conditional_branches_completed = set()
        current_addr = disassembly.addrs[0]
        max_addr = current_addr
        while current_addr:
            if isinstance(disassembly[current_addr], Decoded):
                current_addr = disassembly.seek_addr(current_addr, 1)
                continue
            max_addr = max(max_addr, current_addr)
            inst = disassembly[current_addr]
            code_coverage.add(current_addr)
            # Capture branching instructions
            if inst.mnemonic == "b":
                # Unconditional branch
                branch_addr = Address(int(inst.op_str.strip('#'), 0))
                if branch_addr > max_addr:
                    current_addr = branch_addr
                else:
                    current_addr = disassembly.seek_addr(current_addr, 1)
            elif inst.mnemonic.startswith("b") and inst.mnemonic[1:] in ARM.conditional_suffices:
                # Conditional branch
                conditional_branches_remaining.add(current_addr)
                current_addr = disassembly.seek_addr(current_addr, 1)
            else:
                current_addr = disassembly.seek_addr(current_addr, 1)
        # For all the conditional branching instructions, take the alternative path
        while len(conditional_branches_remaining) > 0:
            conditional_branch_addr = conditional_branches_remaining.pop()
            conditional_branches_completed.add(conditional_branch_addr)
            conditional_branch_inst = disassembly[conditional_branch_addr]
            branch_addr = Address(int(conditional_branch_inst.op_str.strip('#'), 0))
            current_addr = branch_addr
            max_addr = current_addr
            while current_addr and isinstance(disassembly[current_addr], Instruction) and current_addr not in code_coverage:
                max_addr = max(max_addr, current_addr)
                inst = disassembly[current_addr]
                code_coverage.add(current_addr)
                # Capture branching instructions
                if inst.mnemonic == "b":
                    # Unconditional branch
                    branch_addr = Address(int(inst.op_str.strip('#'), 0))
                    if branch_addr > max_addr:
                        current_addr = branch_addr
                    else:
                        current_addr = disassembly.seek_addr(current_addr, 1)
                elif inst.mnemonic.startswith("b") and inst.mnemonic[1:] in ARM.conditional_suffices:
                    # Conditional branch
                    if current_addr not in conditional_branches_completed:
                        conditional_branches_remaining.add(current_addr)
                        current_addr = disassembly.seek_addr(current_addr, 1)
                else:
                    current_addr = disassembly.seek_addr(current_addr, 1)

        # Replace all unreached code with decoded
        for addr in disassembly:
            if isinstance(disassembly[addr], Decoded):
                continue
            if addr not in code_coverage:
                disassembly[addr] = Decoded(disassembly[addr].bytes)
        return disassembly

class BinaryReader:
    def __init__(self):
        pass

    def unfold(self, directory):
        for sub_dir in os.listdir(directory):
            sub_dir_path = os.path.join(directory, sub_dir)
            if not os.path.isdir(sub_dir_path):
                continue
            for file_in_sub_dir in os.listdir(sub_dir_path):
                src_path = os.path.join(sub_dir_path, file_in_sub_dir)
                assert ('.' in file_in_sub_dir), "File {} does not have extension".format(src_path)
                filename_extension = file_in_sub_dir.rsplit('.', 1)[-1]
                dst_path = os.path.join(directory, '.'.join((sub_dir, filename_extension)))
                shutil.copy2(src_path, dst_path)
            shutil.rmtree(sub_dir_path)

    def read_dir(self, directory, unfold=False, extension=None):
        if unfold:
            self.unfold(directory)
        file_binary = {}
        for filename in os.listdir(directory):
            if '.' in filename:
                base_filename, ext = filename.rsplit('.', 1)
            else:
                base_filename = filename
                ext = ''
            if extension is not None:
                if type(extension) is str:
                    if extension != ext:
                        continue
                elif ext not in extension:
                    continue
            file_binary[base_filename] = Binary(filename=os.path.join(directory, filename))
        return file_binary

class BinaryComparator:
    def __init__(self, bins=None):
        self.bins = bins

    def diff(self, aggregate=False, granularity=1):
        diffs = set()
        # Iterate through every pair of binaries
        for bin1, bin2 in combinations(self.bins, 2):
            bin1, bin2 = bin1.get(), bin2.get()
            if len(bin1) != len(bin2):
                # The difference in length will be treated as different bytes
                min_len = min(len(bin1), len(bin2))
                max_len = max(len(bin1), len(bin2))
                for i in range(min_len, max_len):
                    diffs.add(i)
                # Trim the binaries to have the same length
                bin1 = bin1[:min_len]
                bin2 = bin2[:min_len]
            for position in range(len(bin1)):
                c1 = bin1[position]
                c2 = bin2[position]
                if c1 != c2:
                    diffs.add(position)
        diffs = sorted(diffs)
        if aggregate:
            diff_intervals = []
            if len(diffs) == 0:
                return diff_intervals
            pos_start = diffs[0]
            for i in range(1, len(diffs)):
                if diffs[i] - diffs[i-1] > granularity:
                    diff_intervals.append((pos_start, diffs[i-1]))
                    pos_start = diffs[i]
                elif i == len(diffs) - 1:
                    diff_intervals.append((pos_start, diffs[i]))
            return diff_intervals
        else:
            return diffs
