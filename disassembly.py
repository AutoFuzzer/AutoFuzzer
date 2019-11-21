#!/usr/bin/env python3
import os
import binascii
import struct
from collections import defaultdict

from dtype import *
from arm import *
from automaton import State, Transition

class Instruction(object):
    def __init__(self, bytes, mnemonic, op_str):
        self.__bytes = bytes
        self.__mnemonic = mnemonic
        self.__op_str = op_str

    @property
    def bytes(self):
        return self.__bytes

    @property
    def mnemonic(self):
        return self.__mnemonic

    @property
    def op_str(self):
        return self.__op_str

    def __str__(self):
        bytes_str = binascii.hexlify(self.bytes)
        return "{}\t{}\t{}".format(bytes_str, self.mnemonic, self.op_str)

    def __repr__(self):
        return "{}({})".format(self.__class__.__name__, self.__str__())

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if self.bytes != other.bytes:
            return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

class Decoded(object):
    def __init__(self, bytes, bit=32):
        self.__bytes = bytes
        self.__bit = 32

    @property
    def bytes(self):
        return self.__bytes

    @property
    def value(self):
        return struct.unpack("<L", self.bytes)[0]

    @property
    def Value(self):
        return Value(struct.unpack("<L", self.bytes)[0])

    @property
    def hex_str(self):
        formatter = "0x{:0" + str(self.bit // 4) + "x}"
        return formatter.format(self.value)

    @property
    def decoded(self):
        decoded_str = ""
        for ordinal in self.bytes:
            c = chr(ordinal)
            if 32 <= ordinal <= 126:
                decoded_str += c
            else:
                decoded_str += '.'
        return decoded_str

    @property
    def bit(self):
        return self.__bit

    def __str__(self):
        bytes_str = binascii.hexlify(self.bytes)
        return "{}\t{}\t{}".format(bytes_str, self.hex_str, self.decoded)

    def __repr__(self):
        return "{}({})".format(self.__class__.__name__, self.__str__())

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if self.bytes != other.bytes:
            return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

class DisassemblyBase(object):
    def __init__(self, fromfile=None):
        self.__disassembly = {}
        self.__addrs = None
        self.__addr_index = None
        if fromfile:
            self.fromfile(fromfile)

    @property
    def addrs(self):
        if self.__addrs is None:
            self.__addrs = list(sorted(self.__disassembly.keys()))
        return self.__addrs

    @ property
    def addr_index(self):
        if self.__addr_index is None:
            self.__addr_index = {addr: index for index, addr in enumerate(self.addrs)}
        return self.__addr_index

    def __getitem__(self, key):
        if isinstance(key, slice):
            sliced_disassembly = self.__class__()
            for addr in self:
                if addr < key.start:
                    continue
                if addr >= key.stop:
                    break
                sliced_disassembly[addr] = self[addr]
            return sliced_disassembly
        else:
            key = Address(key)
            return self.__disassembly[key]

    def __setitem__(self, key, value):
        key = Address(key)
        if key not in self.__disassembly:
            self.__addrs = None
            self.__addr_index = None
        self.__disassembly[key] = value

    def __delitem__(self, key):
        key = Address(key)
        del self.__disassembly[key]
        self.__addrs = None
        self.__addr_index = None

    def __getslice__(self, i, j):
        return self.__getitem__(slice(i, j))

    def __iter__(self):
        for addr in self.addrs:
            yield addr

    def __len__(self):
        return len(self.__disassembly)

    def __contains__(self, key):
        key = Address(key)
        return key in self.__disassembly

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if len(self) != len(other):
            return False
        for addr1, addr2 in zip(self, other):
            if self[addr1] != other[addr2]:
                return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return '\n'.join(["{}: {}\t{}".format(
            "code" if isinstance(self[addr], Instruction) else (
                "data" if isinstance(self[addr], Decoded) else "unknown"
                ),
            addr, self[addr]) for addr in self])

    def fromfile(self, filename):
        with open(filename, 'r') as f:
            for line in f:
                try:
                    tag_addr, b, mnemonic, op_str = line.strip('\n').split('\t')
                except:
                    continue
                tag, addr = tag_addr.split(': ')
                addr = Address(int(addr, 0))
                b = binascii.unhexlify(b)
                if tag == "code":
                    inst = Instruction(b, mnemonic, op_str)
                elif tag == "data":
                    b = bytearray(b)
                    inst = Decoded(b)
                self[addr] = inst

    def seek_addr(self, addr, offset):
        if addr in self.addr_index:
            index = self.addr_index[addr]
        else:
            raise ValueError("Address {} not in disassembly".format(addr))
        new_index = index + offset
        if 0 <= new_index < len(self.addrs):
            return self.addrs[new_index]
        else:
            return None

    def accessing(self, target_addr, access_type={"ldr"}):
        all_accessings = []
        for addr in self:
            inst = self[addr]
            if isinstance(inst, Instruction):
                if inst.mnemonic in access_type and inst.op_str.split(',', 1)[1].strip().startswith("[pc, #"):
                    ref_addr_str = inst.op_str.split(',', 1)[1].strip().strip("[]").split(',')[1].strip().strip("#")
                    ref_addr = addr + 8 + int(ref_addr_str, 0)
                    if target_addr == ref_addr:
                        all_accessings.append(addr)
        return all_accessings

    def save(self, filename):
        with open(filename, 'w') as f:
            for addr in self:
                content = self[addr]
                if isinstance(content, Instruction):
                    tag = "code"
                elif isinstance(content, Decoded):
                    tag = "data"
                else:
                    tag = "unknown"
                f.write("{}: {}\t{}\n".format(tag, addr, self[addr]))

class DisassemblyHeader(DisassemblyBase):
    pass

class DisassemblySegment(DisassemblyBase):
    pass

class DisassemblySubroutine(DisassemblyBase):
    class DisassemblySubroutineHeader(object):
        def __init__(self):
            self.unknown1 = None
            self.magic_number = None
            self.loading_address = None
            self.unknown2 = None
            self.length = None

        def __str__(self):
            return '\n'.join([
                    "Magic number: {}".format(self.magic_number),
                    "Loading address: {}".format(self.loading_address),
                    "Length: {}".format(self.length)
                    ])

    def __init__(self, fromfile=None):
        self.__header = None
        self.__code = None
        self.__data = None
        super(self.__class__, self).__init__(fromfile=fromfile)

    def __setitem__(self, key, value):
        self.__header = None
        self.__code = None
        self.__data = None
        super(self.__class__, self).__setitem__(key, value)

    def __delitem__(self, key):
        self.__header = None
        self.__code = None
        self.__data = None
        super(self.__class__, self).__delitem__(key, value)

    @property
    def header(self):
        if self.__header is None:
            self.__header = self.__class__.DisassemblySubroutineHeader()
            self.__header.unknown1 = self[self.addrs[0]]
            self.__header.magic_number = self[self.addrs[1]].hex_str
            self.__header.loading_address = Address(int(self[self.addrs[2]].hex_str, 0))
            self.__header.unknown2 = self[self.addrs[3]]
            self.__header.length = int(self[self.addrs[4]].hex_str, 0)
        return self.__header

    @property
    def code(self):
        if self.__code is None:
            self.__code = DisassemblySegment()
            for addr in self:
                if isinstance(self[addr], Instruction):
                    self.__code[addr] = self[addr]
        return self.__code

    @property
    def data(self):
        if self.__data is None:
            self.__data = DisassemblySegment()
            for addr in self.addrs[5:]:
                if isinstance(self[addr], Decoded):
                    self.__data[addr] = self[addr]
        return self.__data


class FunctionBlockInfo(object):
    def __init__(self):
        self.base_addr = None
        self.name = None

function_block_footprint = {
        "R_TRIG": {
            0x4: "CLK",
            0x5: "Q",
            },
        "F_TRIG": {
            0x4: "CLK",
            0x5: "Q",
            },
        "SR": {
            0x4: "SET1",
            0x5: "RESET",
            0x6: "Q1",
            },
        "RS": {
            0x4: "SET",
            0x5: "RESET1",
            0x6: "Q1",
            },
        "TP": {
            0x4: "IN",
            0x8: "PT",
            0xc: "Q",
            0x10: "ET",
            },
        "TON": {
            0x4: "IN",
            0x8: "PT",
            0xc: "Q",
            0x10: "ET",
            },
        "TOF": {
            0x4: "IN",
            0x8: "PT",
            0xc: "Q",
            0x10: "ET",
            },
        "CTU": {
            0x4: "CU",
            0x5: "RESET",
            0x6: "PV",
            0x8: "Q",
            },
        "CTD": {
            0x4: "CD",
            0x5: "LOAD",
            0x6: "PV",
            0x8: "Q",
            },
        }

class Disassembly(DisassemblyBase):
    def __init__(self, fromfile=None):
        self.__header = None
        self.__subroutines = None
        super(self.__class__, self).__init__(fromfile=fromfile)

    @property
    def header(self):
        # TODO: find header length to know how much to read
        if self.__header is None:
            first_addr = None
            addr_buffer = []
            for addr in self:
                if isinstance(self[addr], Instruction):
                    break
                if first_addr is None:
                    first_addr = addr
                addr_buffer.append(addr)
                addr_buffer = addr_buffer[-5:]
            self.__header = DisassemblyHeader()
            for addr in self[first_addr:addr_buffer[0]]:
                self.__header[addr] = self[addr]
        return self.__header

    @property
    def subroutines(self):
        if self.__subroutines is None:
            self.__subroutines = []
            subroutine_header_addrs = []
            code_start_addr = None
            for addr in self:
                # skip header
                if addr in self.header:
                    continue
                if code_start_addr is None:
                    if isinstance(self[addr], Instruction):
                        code_start_addr = addr
                    else:
                        subroutine_header_addrs.append(addr)
                        subroutine_header_addrs = subroutine_header_addrs[-5:]
                        # TODO: How to parse the information before the jumping
                        # table subroutine?
                else:
                    subroutine_len = int(self[subroutine_header_addrs[-1]].hex_str, 0)
                    if addr - code_start_addr >= subroutine_len:
                        subroutine = DisassemblySubroutine()
                        for subroutine_addr in self[subroutine_header_addrs[0]:addr]:
                            subroutine[subroutine_addr] = self[subroutine_addr]
                        self.__subroutines.append(subroutine)
                        subroutine_header_addrs = [addr]  # current addr belongs to the first line of next subroutine header
                        code_start_addr  = None
            # TODO: what to do with the trailing information?
        return self.__subroutines

    def __setitem__(self, key, value):
        super(self.__class__, self).__setitem__(key, value)
        self.__header = None
        self.__subroutines = None

    def __delitem__(self, key):
        super(self.__class__, self).__delitem__(key, value)
        self.__header = None
        self.__subroutines = None

    def index(self, addr=None, subroutine=None):
        if addr:
            for index, subroutine in enumerate(self.subroutines):
                if addr in subroutine:
                    return index
        elif subroutine:
            for index, self_subroutine in enumerate(self.subroutines):
                if self_subroutine == subroutine:
                    return index
        return None

    def get_parser(self, function_block_dir):
        '''
        function_block_dir is the directory containing the .lst file for all function blocks
        '''
        parser = Parser(self)

        n_subroutines = len(self.subroutines)
        n_function_blocks = (n_subroutines - 119 ) // 5

        # Build jumping table
        jumping_table_subroutine = self.subroutines[-2]
        subroutine_entry_counter = 3
        subroutine_exit_counter = 2
        def jumping_table_ldr_hook(sim, addr):
            return jumping_table_subroutine.data[addr].Value
        def jumping_table_str_hook(sim, addr, value):
            parser.jumping_table[addr] = value
        mem_hook = MemoryHook(jumping_table_ldr_hook, jumping_table_str_hook)
        arm = ARM(mem_hook=mem_hook)
        current_addr = jumping_table_subroutine.code.addrs[0]
        while current_addr:
            inst = jumping_table_subroutine.code[current_addr]

            # Skip the subroutine entry
            if subroutine_entry_counter == 3:
                if inst.mnemonic == "push" and inst.op_str == "{sl, lr}":
                    subroutine_entry_counter -= 1
                    current_addr = jumping_table_subroutine.code.seek_addr(current_addr, 1)
                    continue
                else:
                    raise Exception("Unseen subroutine entry at {}: {}".format(current_addr, inst))
            elif subroutine_entry_counter == 2:
                if inst.mnemonic == "mov" and inst.op_str == "sl, sp":
                    subroutine_entry_counter -= 1
                    current_addr = jumping_table_subroutine.code.seek_addr(current_addr, 1)
                    continue
                else:
                    raise Exception("Unseen subroutine entry at {}: {}".format(current_addr, inst))
            elif subroutine_entry_counter == 1:
                if inst.mnemonic == "push":
                    subroutine_entry_counter -= 1
                    stack_push_at_entry = inst.op_str
                    current_addr = jumping_table_subroutine.code.seek_addr(current_addr, 1)
                    continue
                else:
                    raise Exception("Unseen subroutine entry at {}: {}".format(current_addr, inst))

            # Skip the subroutine exit
            if inst.mnemonic == "pop":
                if subroutine_exit_counter == 2:
                    if inst.op_str != stack_push_at_entry:
                        raise Exception("Stack pop does not match stack push at {}: {}".format(current_addr, inst))
                elif subroutine_exit_counter == 1:
                    if inst.op_str != "{sl, pc}":
                        raise Exception("Unseen subroutine exit at {}: {}".format(current_addr, inst))
                elif subroutine_exit_counter < 0:
                    raise Exception("Unseen subroutine exit at {}: {}".format(current_addr, inst))
                subroutine_exit_counter -= 1
                current_addr = jumping_table_subroutine.code.seek_addr(current_addr, 1)
                continue

            branch_addr = arm.execute(current_addr, inst)
            if branch_addr is None:
                current_addr = jumping_table_subroutine.code.seek_addr(current_addr, 1)
            else:
                current_addr = branch_addr

        # Read known function block subroutines
        function_blocks = {}
        for function_block_file in os.listdir(function_block_dir):
            function_block_name = function_block_file.split('.')[0]
            function_blocks[function_block_name] = DisassemblySegment(fromfile=os.path.join(function_block_dir, function_block_file))
        # Identify which function block each subroutine address corresponds to
        subroutine_addr_function_block = {}
        for index in range(26, 26 + n_function_blocks):
            function_block_subroutine = self.subroutines[index]
            function_block_found = False
            for function_block_name, function_block_code in function_blocks.items():
                if function_block_code == function_block_subroutine.code:
                    subroutine_addr_function_block[function_block_subroutine.header.loading_address] = function_block_name
                    function_block_found = True
                    break
            if not function_block_found:
                raise Exception("Unknown function block subroutine at {}".format(self.subroutines[index].addrs[0]))

        # Save mapping between the function block calling address in the
        # program subroutine and the function block name
        for mem_addr, jump_addr in parser.jumping_table.items():
            if jump_addr in subroutine_addr_function_block:
                parser.function_block_addr_name[mem_addr] = subroutine_addr_function_block[jump_addr]

        # Scan input/output/internal vars in the program
        program_subroutine = self.subroutines[25]
        subroutine_entry_counter = 3
        subroutine_exit_counter = 2
        stack_push_at_entry = None
        in_function_block = False
        read_io = set()
        write_io = set()
        read_non_io = set()
        write_non_io = set()
        function_block_counter = defaultdict(int)
        function_block_info = FunctionBlockInfo()
        def ldr_hook(sim, addr):
            if addr in program_subroutine.data:
                return program_subroutine.data[addr].Value
            elif addr in parser.const_lut:
                return parser.const_lut[addr]
            elif addr in parser.jumping_table:
                if function_block_info.name is None:
                    function_block_info.name = subroutine_addr_function_block[parser.jumping_table[addr]]
                    return parser.jumping_table[addr]
                else:
                    raise Exception("Unhandled function block name: {}".format(function_block_info.name))
            else:
                if addr <= 0x10:    # Likely an obfuscated I/O address
                    read_io.add(sim.last_fp_ldr_from_addr)   # Stores the address which holds the I/O address
                elif addr == 0xDEADBEEB:    # Likely a read from the stack
                    # The value 0xDEADBEE0 is used because sometimes the stack
                    # is used to store intermediate values, such as when
                    # converting the data types from unsigned to signed. The SP
                    # will be offset by 4 from its original value 0xDEADBEEF.
                    # Such instructions do not correspond to variable read
                    pass
                else:   # Likely an internal var address
                    read_non_io.add(addr)   # Stores the actual address of the variable
            return Value(0)
        def str_hook(sim, addr, value):
            if in_function_block:
                if addr == 0xDEADBEEF:  # Writing to SP register (preparing for function block call)
                    if function_block_info.base_addr is None:
                        function_block_info.base_addr = Address(value.value)
                    else:
                        raise Exception("Unhandled function block struct base address: {}".format(function_block_info.base_addr))
            else:
                if addr <= 0x10:    # Likely an obfuscated I/O address
                    write_io.add(sim.last_fp_ldr_from_addr)   # Stores the address which holds the I/O address
                elif addr == 0xDEADBEEB:    # Likely a read from the stack
                    # The value 0xDEADBEE0 is used because sometimes the stack
                    # is used to store intermediate values, such as when
                    # converting the data types from unsigned to signed. The SP
                    # will be offset by 4 from its original value 0xDEADBEEF.
                    # Such instructions do not correspond to variable writes
                    pass
                else:   # Likely an internal var address
                    write_non_io.add(addr)   # Stores the actual address of the variable
        mem_hook = MemoryHook(ldr_hook, str_hook)
        arm = ARM(mem_hook=mem_hook)
        arm.registers["sp"] = Value(0xDEADBEEF)    # Marker for SP register value
        current_addr = program_subroutine.code.addrs[0]
        while current_addr:
            inst = program_subroutine.code[current_addr]

            # Skip the subroutine entry
            if subroutine_entry_counter == 3:
                if inst.mnemonic == "push" and inst.op_str == "{sl, lr}":
                    subroutine_entry_counter -= 1
                    current_addr = program_subroutine.code.seek_addr(current_addr, 1)
                    continue
                else:
                    raise Exception("Unseen subroutine entry at {}: {}".format(current_addr, inst))
            elif subroutine_entry_counter == 2:
                if inst.mnemonic == "mov" and inst.op_str == "sl, sp":
                    subroutine_entry_counter -= 1
                    current_addr = program_subroutine.code.seek_addr(current_addr, 1)
                    continue
                else:
                    raise Exception("Unseen subroutine entry at {}: {}".format(current_addr, inst))
            elif subroutine_entry_counter == 1:
                if inst.mnemonic == "push" and all(rn.startswith('r') and rn.strip('r').isdigit() for rn in inst.op_str.strip('{}').split(', ')):
                    subroutine_entry_counter -= 1
                    stack_push_at_entry = inst.op_str
                    current_addr = program_subroutine.code.seek_addr(current_addr, 1)
                    continue
                else:
                    raise Exception("Unseen subroutine entry at {}: {}".format(current_addr, inst))

            # Skip the subroutine exit
            if inst.mnemonic == "pop":
                if subroutine_exit_counter == 2:
                    if inst.op_str != stack_push_at_entry:
                        raise Exception("Stack pop does not match stack push at {}: {}".format(current_addr, inst))
                elif subroutine_exit_counter == 1:
                    if inst.op_str != "{sl, pc}":
                        raise Exception("Unseen subroutine exit at {}: {}".format(current_addr, inst))
                elif subroutine_exit_counter < 0:
                    raise Exception("Unseen subroutine exit at {}: {}".format(current_addr, inst))
                subroutine_exit_counter -= 1
                current_addr = program_subroutine.code.seek_addr(current_addr, 1)
                continue

            # Check whether the current code is function block:
            if not in_function_block:
                # Condition for starting a function block
                if inst.mnemonic == "sub" and inst.op_str == "sp, sp, #4":
                    in_function_block = True
                    current_addr = program_subroutine.code.seek_addr(current_addr, 1)
                    continue
            else:
                # Condition for terminating a function block
                if inst.mnemonic == "add" and inst.op_str == "sp, sp, #4":
                    if function_block_info.base_addr is None:
                        raise Exception("No function block struct base address detected at {}".format(current_addr))
                    if function_block_info.name is None:
                        raise Exception("No function block name detected at: {}".format(current_addr))
                    function_block_index = function_block_counter[function_block_info.name]
                    function_block_symbol = "{}{}".format(function_block_info.name, function_block_index)
                    if function_block_info.base_addr in parser.function_block_addr_base_symbol:
                        raise Exception("{} already exists: {}".format(
                            function_block_info.base_addr,
                            parser.function_block_addr_base_symbol[function_block_info.base_addr]))
                    parser.function_block_addr_base_symbol[function_block_info.base_addr] = function_block_symbol
                    for offset, field in function_block_footprint[function_block_info.name].items():
                        field_addr = function_block_info.base_addr + offset
                        field_name = "{}.{}".format(function_block_symbol, field)
                        if field_addr in parser.function_block_addr_field:
                            raise Exception("{} already exists: {}".format(
                                field_addr,
                                parser.function_block_addr_field[field_addr]
                                ))
                        parser.function_block_addr_field[field_addr] = field_name
                        if field_name in parser.function_block_field_addr:
                            raise Exception("{} alredy exists: {}".format(
                                field_name,
                                parser.function_block_field_addr[field_name]
                                ))
                        parser.function_block_field_addr[field_name] = field_addr
                    function_block_counter[function_block_info.name] += 1
                    function_block_info.base_addr = None
                    function_block_info.name = None
                    in_function_block = False
                    current_addr = program_subroutine.code.seek_addr(current_addr, 1)
                    continue

            branch_addr = arm.execute(current_addr, inst)
            # Ignore branching to expand code coverage
            current_addr = program_subroutine.code.seek_addr(current_addr, 1)
            #if branch_addr is None:
            #    current_addr = program_subroutine.code.seek_addr(current_addr, 1)
            #else:
            #    current_addr = branch_addr

        # Check if there is a collision (multiple write to the same obfuscated
        # I/O address stored at different memory location).
        # Mark all I/O addresses which have been written to as output addresses
        write_io_addr = {}
        for ref_addr in write_io:
            write_addr = Address(self[ref_addr].value)
            if write_addr not in write_io_addr:
                write_io_addr[write_addr] = ref_addr
                parser.output_addrs[ref_addr] = write_addr.value    # output index, e.g., QX0
            else:
                raise Exception("I/O write collission: {}: {}\t {}: {}".format(
                    write_io_addr[write_addr],
                    write_addr,
                    ref_addr,
                    write_addr
                    ))
        # Mark the I/O addresses which have never been written to as input addresses
        for ref_addr in read_io:
            if ref_addr not in write_io:
                read_addr = Address(self[ref_addr].value)
                parser.input_addrs[ref_addr] = read_addr.value  # input index, e.g., IX0
        # Save all addresses which have been written to as the internal variables
        # (except output, and those inside a function block)
        # Check if each non I/O address has been both written to and read from
        for write_addr in write_non_io:
            #if (write_addr not in read_non_io
            #        and write_addr not in parser.function_block_addr_field):
            #    print("Warning: write-only non I/O address: {}".format(
            #        write_addr))
            parser.internal_vars[write_addr] = Value(0)

        # Build constant lookup table and initialize the internal variables
        var_init_subroutine = self.subroutines[-8]
        def ldr_hook(sim, addr):
            if addr in var_init_subroutine.data:
                return var_init_subroutine.data[addr].Value
            elif addr in parser.const_lut:
                return parser.const_lut[addr]
            elif addr in parser.jumping_table:
                return parser.jumping_table[addr]
            return Value(0)
        def str_hook(sim, addr, value):
            if addr.value in parser.output_addrs.values():
                parser.default_outputs[addr.value] = value
            elif addr in parser.internal_vars:
                parser.default_internal_vars[addr] = value
            else:
                parser.const_lut[addr] = value
        arm = ARM(mem_hook=MemoryHook(ldr_hook, str_hook))
        current_addr = var_init_subroutine.code.addrs[0]
        while current_addr:
            inst = var_init_subroutine.code[current_addr]
            skip = False
            for keyword in {"push", "pop"}:
                if keyword == inst.mnemonic:
                    skip = True
                    break
            for keyword in {"sl", "lr", "sp"}:
                if keyword in inst.op_str:
                    skip = True
                    break
            if skip:
                current_addr = var_init_subroutine.code.seek_addr(current_addr, 1)
                continue
            branch_addr = arm.execute(current_addr, inst)
            if branch_addr is None:
                current_addr = var_init_subroutine.code.seek_addr(current_addr, 1)
            else:
                current_addr = branch_addr

        # Check if each non I/O address has been both written to and read from
        #for read_addr in read_non_io:
        #    if (read_addr not in write_non_io
        #            and read_addr not in parser.function_block_addr_field
        #            and read_addr not in parser.const_lut):
        #        print("Warning: read-only non I/O address: {}".format(
        #            read_addr))

        parser.reset()

        return parser

parser_debug_help_msg = '\n'.join([
        "   s, step         single step the instruction",
        "   c, cycle        execute a single scan cycle",
        "   r, register     print all register values",
        "   f, flag         print all flag values",
        "   j, jumping      print the entire jumping table",
        "      j addr       print the entry containing 'addr' in the jumping table",
        "      jumping addr",
        "   const           print the entire const look-up table",
        "      const addr   print the entry containing 'addr' in the const look-up table",
        "   i, input        print all input values",
        "      i index      print input[index] value",
        "      input index",
        "   o, output       print all output values",
        "      o index      print output[index] value",
        "      output index",
        "   v, variable     print all internal variable values",
        "      v addr       print variable[addr] value",
        "      variable addr",
        "   fbs             print all function block states",
        "      fbs symbol   print function_block[symbol] state",
        "   fbv             print all function block field values",
        "      fbv field    print function_block[field] value",
        "   timer           print all active timers",
        "   counter         print all active counters",
        "   tc              print all active timers and counters",
        ])

class Parser(object):
    def __init__(self, disassembly):
        self.disassembly = disassembly
        self.program_subroutine = self.disassembly.subroutines[25]
        self.jumping_table = {}
        self.const_lut = {}
        self.input_addrs = {}
        self.output_addrs = {}
        self.default_outputs = {}
        self.default_internal_vars = {}
        self.function_block_addr_name = {}
        self.function_block_addr_base_symbol = {}
        self.function_block_field_addr = {}
        self.function_block_addr_field = {}
        self.function_block_field_val = {}

        self.__state = State()
        self.__transition = Transition()

        self.__single_stepping = False

        self.function_block_info = FunctionBlockInfo()
        self.stack = {}
        def ldr_hook(sim, addr):
            if addr in self.program_subroutine.data:
                return self.program_subroutine.data[addr].Value
            elif addr in self.const_lut:
                return self.const_lut[addr]
            elif addr in self.jumping_table:
                if self.function_block_info.name is None:
                    self.function_block_info.name = self.function_block_addr_name[addr]
                    return self.jumping_table[addr]
                else:
                    raise Exception("Unhandled function block name: {}".format(self.function_block_info.name))
            elif addr <= 0x10:      # Likely an obfuscated I/O address
                fp = self.arm.last_fp_ldr_from_addr
                if fp in self.input_addrs:
                    return self.inputs[addr.value]
                elif fp in self.output_addrs:
                    return self.outputs[addr.value]
                else:
                    raise Exception("Unknown address: {}".format(addr))
            elif addr in self.internal_vars:
                return self.internal_vars[addr]
            elif addr in self.function_block_addr_field:
                return self.function_block_field_val[self.function_block_addr_field[addr]]
            elif addr == 0xDEADBEEB:
                # Intermediate value stored in the stack
                return self.stack[addr]
            return Value(0)
        def str_hook(sim, addr, value):
            if addr == 0xDEADBEEF:  # Writing to SP register (preparing for function block call)
                if self.function_block_info.base_addr is None:
                    self.function_block_info.base_addr = Address(value.value)
                else:
                    raise Exception("Unhandled function block struct base address: {}".format(self.function_block_info.base_addr))
            elif addr <= 0x10:      # Likely an obfuscated I/O address
                fp = self.arm.last_fp_ldr_from_addr
                if fp in self.input_addrs:
                    raise Exception("Writing to input address: {}".format(addr))
                elif fp in self.output_addrs:
                    self.outputs[addr.value] = value
                else:
                    raise Exception("Unknown address: {}".format(addr))
            elif addr in self.internal_vars:
                self.internal_vars[addr] = value
            elif addr in self.function_block_addr_field:
                self.function_block_field_val[self.function_block_addr_field[addr]] = value
            elif addr == 0xDEADBEEB:
                # Intermediate value stored in the stack
                self.stack[addr] = value
            else:
                raise Exception("Unknown write address: {}".format(addr))
        self.arm = ARM(mem_hook=MemoryHook(ldr_hook, str_hook))
        self.arm.registers["sp"] = Value(0xDEADBEEF)    # Marker for SP register value

    @property
    def state(self):
        return self.__state.copy()

    @property
    def outputs(self):
        return self.__state.outputs

    @property
    def internal_vars(self):
        return self.__state.internal_vars

    @property
    def function_block_states(self):
        return self.__state.function_block_states

    @property
    def transition(self):
        return self.__transition.copy()

    @property
    def inputs(self):
        return self.__transition.inputs

    @property
    def timers(self):
        return self.__transition.timers

    @property
    def counters(self):
        return self.__transition.counters

    def __run_function_block__(self, name, base_addr):
        symbol = self.function_block_addr_base_symbol[base_addr]
        if name == "R_TRIG":
            CLK = False if self.function_block_field_val["{}.CLK".format(symbol)] == 0 else True
            if not self.function_block_states[symbol] and CLK:
                self.function_block_field_val["{}.Q".format(symbol)] = Value(1)
            else:
                self.function_block_field_val["{}.Q".format(symbol)] = Value(0)
            self.function_block_states[symbol] = CLK
        elif name == "F_TRIG":
            CLK = False if self.function_block_field_val["{}.CLK".format(symbol)] == 0 else True
            if self.function_block_states[symbol] and not CLK:
                self.function_block_field_val["{}.Q".format(symbol)] = Value(1)
            else:
                self.function_block_field_val["{}.Q".format(symbol)] = Value(0)
            self.function_block_states[symbol] = CLK
        elif name == "SR":
            SET1 = False if self.function_block_field_val["{}.SET1".format(symbol)] == 0 else True
            RESET = False if self.function_block_field_val["{}.RESET".format(symbol)] == 0 else True
            if SET1:
                self.function_block_field_val["{}.Q1".format(symbol)] = Value(1)
                self.function_block_states[symbol] = True
            elif RESET:
                self.function_block_field_val["{}.Q1".format(symbol)] = Value(0)
                self.function_block_states[symbol] = False
        elif name == "RS":
            SET = False if self.function_block_field_val["{}.SET".format(symbol)] == 0 else True
            RESET1 = False if self.function_block_field_val["{}.RESET1".format(symbol)] == 0 else True
            if RESET1:
                self.function_block_field_val["{}.Q1".format(symbol)] = Value(0)
                self.function_block_states[symbol] = False
            elif SET:
                self.function_block_field_val["{}.Q1".format(symbol)] = Value(1)
                self.function_block_states[symbol] = True
        elif name == "TP":
            IN = False if self.function_block_field_val["{}.IN".format(symbol)] == 0 else True
            PT = self.function_block_field_val["{}.PT".format(symbol)]
            if not self.function_block_states[symbol][0] and IN:
                # Activate the output and start the timer
                self.function_block_field_val["{}.Q".format(symbol)] = Value(1)
                self.timers[symbol] = PT
            else:
                # Deactivate output and reset the timer
                self.function_block_field_val["{}.Q".format(symbol)] = Value(0)
                if symbol in self.timers:
                    self.timers.pop(symbol)
            # Record the last IN
            self.function_block_states[symbol] = (IN, self.function_block_field_val["{}.Q".format(symbol)] == 1)
        elif name == "TON":
            IN = False if self.function_block_field_val["{}.IN".format(symbol)] == 0 else True
            PT = self.function_block_field_val["{}.PT".format(symbol)]
            if IN:
                if not self.function_block_states[symbol][0]:
                    # Turning on
                    # Start the timer
                    self.timers[symbol] = PT
                else:
                    # Activate output
                    self.function_block_field_val["{}.Q".format(symbol)] = Value(1)
                    # Reset the timer
                    if symbol in self.timers:
                        self.timers.pop(symbol)
            else:
                # Deactivate the output
                self.function_block_field_val["{}.Q".format(symbol)] = Value(0)
                # Reset the timer
                if symbol in self.timers:
                    self.timers.pop(symbol)
            # Record the last IN
            self.function_block_states[symbol] = (IN, self.function_block_field_val["{}.Q".format(symbol)] == 1)
        elif name == "TOF":
            IN = False if self.function_block_field_val["{}.IN".format(symbol)] == 0 else True
            PT = self.function_block_field_val["{}.PT".format(symbol)]
            if IN:
                # Activate the output
                self.function_block_field_val["{}.Q".format(symbol)] = Value(1)
                # Reset the timer
                if symbol in self.timers:
                    self.timers.pop(symbol)
            else:
                if self.function_block_states[symbol][0]:
                    # Turning off
                    # Start the timer
                    self.timers[symbol] = PT
                else:
                    # Deactivate output
                    self.function_block_field_val["{}.Q".format(symbol)] = Value(0)
                    # Reset the timer
                    if symbol in self.timers:
                        self.timers.pop(symbol)
            # Record the last state
            self.function_block_states[symbol] = (IN, self.function_block_field_val["{}.Q".format(symbol)] == 1)
        elif name == "CTU":
            CU = False if self.function_block_field_val["{}.CU".format(symbol)] == 0 else True
            RESET = False if self.function_block_field_val["{}.RESET".format(symbol)] == 0 else True
            PV = self.function_block_field_val["{}.PV".format(symbol)]
            if RESET:
                self.function_block_field_val["{}.Q".format(symbol)] = Value(0)
                self.function_block_states[symbol] = False
                if symbol in self.counters:
                    self.counters.pop(symbol)
            elif not self.function_block_states[symbol] and CU:
                self.function_block_field_val["{}.Q".format(symbol)] = Value(1)
                self.function_block_states[symbol] = True
                self.counters[symbol] = PV
        elif name == "CTD":
            CD = False if self.function_block_field_val["{}.CD".format(symbol)] == 0 else True
            RESET = False if self.function_block_field_val["{}.LOAD".format(symbol)] == 0 else True
            PV = self.function_block_field_val["{}.PV".format(symbol)]
            if RESET:
                self.function_block_field_val["{}.Q".format(symbol)] = Value(0)
                self.function_block_states[symbol] = False
                if symbol in self.counters:
                    self.counters.pop(symbol)
            elif not self.function_block_states[symbol] and CD:
                self.function_block_field_val["{}.Q".format(symbol)] = Value(1)
                self.function_block_states[symbol] = True
                self.counters[symbol] = PV
        else:
            raise Exception("Unknown function block: ".format(name))

    def reset(self):
        # Initialize inputs
        for addr, index in self.input_addrs.items():
            self.inputs[index] = Value(0)
        # Initialize outputs
        for index in self.outputs:
            self.outputs[index] = Value(0)
        for index, value in self.default_outputs.items():
            self.outputs[index] = value
        # Initialize internal variables
        for addr in self.internal_vars:
            self.internal_vars[addr] = Value(0)
        for addr, value in self.default_internal_vars.items():
            self.internal_vars[addr] = value
        # Initialize function block fields
        for field in self.function_block_field_addr:
            self.function_block_field_val[field] = Value(0)
        # Initialize function block states
        for addr, symbol in self.function_block_addr_base_symbol.items():
            # For R_TRIG, F_TRIG, value corresponds to the last .CLK
            # For SR, RS, value corresponds to .Q1
            # For TP, TON, TOF, value corresponds to last .IN and activation
            # status
            # For CTU, CTD, value corresponds to activation status
            if symbol.startswith(("TP", "TON", "TOF")):
                self.function_block_states[symbol] = (False, False)
            else:
                self.function_block_states[symbol] = False
        # Clear all timers and counters
        self.timers.clear()
        self.counters.clear()

    def scan_cycle(self, inputs=None, input_bits=8, debug=False):
        '''
        Commence a single scan cycle of the PLC program
        '''
        def debug_wrapper():
            while True:
                rsp = input("debug> ")
                if len(rsp.strip()) == 0:
                    continue
                args = rsp.split()
                if rsp == 's' or rsp == 'step':
                    self.__single_stepping = True
                    break
                elif rsp == 'c' or rsp == 'cycle':
                    self.__single_stepping = False
                    break
                elif rsp == 'r' or rsp == 'register':
                    print(self.arm.registers)
                elif rsp == 'f' or rsp == 'flag':
                    print(self.arm.flags)
                elif rsp == 'j' or rsp == 'jumping':
                    print(self.jumping_table)
                elif (args[0] == 'j' or args[0] == 'jumping') and len(args) == 2:
                    try:
                        addr = Address(int(args[1], 0))
                        print(self.jumping_table[addr])
                    except:
                        print("Key not found in jumping table: {}".format(args[1]))
                elif rsp == 'const':
                    print(self.const_lut)
                elif args[0] == 'const' and len(args) == 2:
                    try:
                        addr = Address(int(args[1], 0))
                        print(self.const_lut[addr])
                    except:
                        print("Key not found in const look-up table: {}".format(args[1]))
                elif rsp == 'i' or rsp == 'input':
                    print(self.inputs)
                elif (args[0] == 'i' or args[0] == 'input') and len(args) == 2:
                    try:
                        index = int(args[1], 0)
                        print(self.inputs[index])
                    except:
                        print("Key not found in input: {}".format(args[1]))
                elif rsp == 'o' or rsp == 'output':
                    print(self.__state.outputs)
                elif (args[0] == 'o' or args[0] == 'output') and len(args) == 2:
                    try:
                        index = int(args[1], 0)
                        print(self.__state.outputs[index])
                    except:
                        print("Key not found in output: {}".format(args[1]))
                elif rsp == 'v' or rsp == 'variable':
                    print(self.__state.internal_vars)
                elif (args[0] == 'v' or args[0] == 'variable') and len(args) == 2:
                    try:
                        addr = Address(int(args[1], 0))
                        print(self.__state.internal_vars[addr])
                    except:
                        print("Key not found in internal variables: {}".format(args[1]))
                elif rsp == 'fbs':
                    print(self.__state.function_block_states)
                elif args[0] == 'fbs' and len(args) == 2:
                    try:
                        symbol = args[1]
                        print(self.__state.function_block_states[symbol])
                    except:
                        print("Key not found in function block states: {}".format(args[1]))
                elif rsp == 'fbv':
                    print(self.function_block_field_val)
                elif args[0] == 'fbv' and len(args) == 2:
                    try:
                        field = args[1]
                        print(self.function_block_field_val[field])
                    except:
                        print("Key not found in function block fields: {}".format(args[1]))
                elif rsp == 'timer':
                    print(self.timers)
                elif rsp == 'counter':
                    print(self.counters)
                elif rsp == 'tc':
                    print("Timers: {}".format(self.timers))
                    print("Counters: {}".format(self.counters))
                else:
                    print("Unknown command: {}".format(rsp))
                    print(parser_debug_help_msg)

        # Update input values
        if isinstance(inputs, Value):
            mask = Value(2**input_bits - 1)
            for index in range(inputs.bit // input_bits):
                if index in self.inputs:
                    self.inputs[index] = inputs & mask
                inputs >>= input_bits
        if debug:
            print("Scan cycle start")
            debug_wrapper()
        # Execute the Logic
        subroutine_entry_counter = 3
        subroutine_exit_counter = 2
        stack_push_at_entry = None
        in_function_block = False
        current_addr = self.program_subroutine.code.addrs[0]
        while current_addr:
            inst = self.program_subroutine.code[current_addr]

            # Skip the subroutine entry
            if subroutine_entry_counter == 3:
                if inst.mnemonic == "push" and inst.op_str == "{sl, lr}":
                    subroutine_entry_counter -= 1
                    current_addr = self.program_subroutine.code.seek_addr(current_addr, 1)
                    continue
                else:
                    raise Exception("Unseen subroutine entry at {}: {}".format(current_addr, inst))
            elif subroutine_entry_counter == 2:
                if inst.mnemonic == "mov" and inst.op_str == "sl, sp":
                    subroutine_entry_counter -= 1
                    current_addr = self.program_subroutine.code.seek_addr(current_addr, 1)
                    continue
                else:
                    raise Exception("Unseen subroutine entry at {}: {}".format(current_addr, inst))
            elif subroutine_entry_counter == 1:
                if inst.mnemonic == "push" and all(rn.startswith('r') and rn.strip('r').isdigit() for rn in inst.op_str.strip('{}').split(', ')):
                    subroutine_entry_counter -= 1
                    stack_push_at_entry = inst.op_str
                    current_addr = self.program_subroutine.code.seek_addr(current_addr, 1)
                    continue
                else:
                    raise Exception("Unseen subroutine entry at {}: {}".format(current_addr, inst))

            # Skip the subroutine exit
            if inst.mnemonic == "pop":
                if subroutine_exit_counter == 2:
                    if inst.op_str != stack_push_at_entry:
                        raise Exception("Stack pop does not match stack push at {}: {}".format(current_addr, inst))
                elif subroutine_exit_counter == 1:
                    if inst.op_str != "{sl, pc}":
                        raise Exception("Unseen subroutine exit at {}: {}".format(current_addr, inst))
                elif subroutine_exit_counter < 0:
                    raise Exception("Unseen subroutine exit at {}: {}".format(current_addr, inst))
                subroutine_exit_counter -= 1
                current_addr = self.program_subroutine.code.seek_addr(current_addr, 1)
                continue

            # Check whether the current code is function block:
            if not in_function_block:
                # Condition for starting a function block
                if inst.mnemonic == "sub" and inst.op_str == "sp, sp, #4":
                    in_function_block = True
                    current_addr = self.program_subroutine.code.seek_addr(current_addr, 1)
                    continue
            else:
                # Condition for terminating a function block
                if inst.mnemonic == "add" and inst.op_str == "sp, sp, #4":
                    if self.function_block_info.base_addr is None:
                        raise Exception("No function block struct base address detected at {}".format(current_addr))
                    if self.function_block_info.name is None:
                        raise Exception("No function block name detected at: {}".format(current_addr))
                    self.__run_function_block__(self.function_block_info.name, self.function_block_info.base_addr)
                    self.function_block_info.base_addr = None
                    self.function_block_info.name = None
                    in_function_block = False
                    current_addr = self.program_subroutine.code.seek_addr(current_addr, 1)
                    continue

            if debug and self.__single_stepping:
                print("{}\t{}".format(current_addr, inst))
            branch_addr = self.arm.execute(current_addr, inst)
            if branch_addr is None:
                current_addr = self.program_subroutine.code.seek_addr(current_addr, 1)
            else:
                current_addr = branch_addr
            if debug and self.__single_stepping:
                debug_wrapper()
