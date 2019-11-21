#!/usr/bin/env python3
from collections import defaultdict

from dtype import *

class MemoryHook(object):
    def __init__(self, ldr_hook, str_hook):
        self.__ldr_hook = ldr_hook
        self.__str_hook = str_hook

    @property
    def ldr(self):
        return self.__ldr_hook

    @property
    def str(self):
        return self.__str_hook

class ARM(object):
    conditional_suffices = {'eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl',
            'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', ''}
    def __init__(self, memory=defaultdict(Value), mem_hook=None):
        self.__registers = {}
        self.__flags = {
                "N": False,
                "Z": False,
                "C": False,
                "V": False,
                }
        self.__memory = memory
        self.__mem_hook = mem_hook
        self.last_fp_ldr_from_addr = None

    def __conditional_execution__(self, suffix):
        # Source: http://davespace.co.uk/arm/introduction-to-arm/conditional.html
        if suffix == "":
            # Original instruction with no suffix
            return True
        if suffix == "eq":
            # Equal: Z
            return self.flags["Z"]
        if suffix == "ne":
            # Not equal: !Z
            return not self.flags["Z"]
        if suffix == "cs":
            # Carry set / unsigned higher or same: C
            return self.flags["C"]
        if suffix == "hs":
            # Carry set / unsigned higher or same: C
            return self.flags["C"]
        if suffix == "cc":
            # Carry clear / unsigned lower: !C
            return not self.flags["C"]
        if suffix == "lo":
            # Carry clear / unsigned lower: !C
            return not self.flags["C"]
        if suffix == "mi":
            # Minus / negative: N
            return self.flags["N"]
        if suffix == "pl":
            # Plus / positive or zero: !N
            return not self.flags["N"]
        if suffix == "vs":
            # Overflow: V
            return self.flags["V"]
        if suffix == "vc":
            # No overflow: !V
            return not self.flags["V"]
        if suffix == "hi":
            # Unsigned higher: C and !Z
            return self.flags["C"] and not self.flags["Z"]
        if suffix == "ls":
            # Unsigned lower or same: !C or Z
            return not self.flags["C"] or self.flags["Z"]
        if suffix == "ge":
            # Signed greater than or equal: N == V
            return self.flags["N"] == self.flags["V"]
        if suffix == "lt":
            # Signed less than: N != V
            return self.flags["N"] != self.flags["V"]
        if suffix == "gt":
            # Signed greater than: !Z and (N == V)
            return not self.flags["Z"] and (self.flags["N"] == self.flags["V"])
        if suffix == "le":
            # Signed less than or equal: Z or (N != V)
            return self.flags["Z"] or (self.flags["N"] != self.flags["V"])
        if suffix == "al":
            # Always (default): any
            return True

    def __decompose_mnemonic__(self, mnemonic):
        '''
        Decompose mnemonic into 'S' appendix and conditions
        '''
        supported_mnemonics = [
                "ldr", "ldrb", "ldrsb", "ldrh", "ldrsh", "str", "strb", "strh", "ldm", "stm",
                "add", "sub", "adc", "sbc", "mul", "and", "orr", "eor", "bic", "lsl", "lsr",
                "mov", "mvn", "cmp", "cmn", "teq", "tst", "b", "bl",
                ]
        for candidate_mnemonic in supported_mnemonics:
            if mnemonic.startswith(candidate_mnemonic):
                if mnemonic == candidate_mnemonic:
                    return candidate_mnemonic, False, ""
                if mnemonic[len(candidate_mnemonic):] in self.conditional_suffices:
                    return candidate_mnemonic, False, mnemonic[len(candidate_mnemonic):]
                if mnemonic[len(candidate_mnemonic):].startswith("s") and mnemonic[len(candidate_mnemonic)+1:] in self.conditional_suffices:
                    return candidate_mnemonic, True, mnemonic[len(candidate_mnemonic)+1:]
        raise Exception("Unknown mnemonic {}".format(mnemonic))

    def execute(self, addr, inst):
        self.registers["pc"] = Value(addr.value) + 8
        mnemonic, update_flags, cond_suffix = self.__decompose_mnemonic__(inst.mnemonic)
        # Check conditional execution
        if self.__conditional_execution__(cond_suffix):
            if mnemonic in {"ldr", "ldrb", "ldrsb", "ldrh", "ldrsh"} and update_flags == False:
                masking = {
                        "ldr": lambda value: value & 0xFFFFFFFF,
                        "ldrb": lambda value: value & 0xFF,
                        "ldrsb": lambda value: value & 0xFF | (0xFFFFFF00 if value >> 7 & 0x1 == 1 else 0),
                        "ldrh": lambda value: value & 0xFFFF,
                        "ldrsh": lambda value: value & 0xFFFF | (0xFFFF0000 if value >> 15 & 0x1 == 1 else 0),
                        }
                Rt, target_addr_str = inst.op_str.split(', ', 1)
                if ',' in target_addr_str:
                    # Assumes pre-indexing only
                    with_update = False
                    if target_addr_str.endswith("!"):
                        # Pre-Indexing with update
                        with_update = True
                        target_addr_str = target_addr_str.strip("!")
                    # Assumes immediate offset only
                    Rn, target_addr_offset_str = target_addr_str.strip("[]").split(', ', 1)
                    offset = int(target_addr_offset_str.strip('#'), 0)
                    target_addr = Address(self.registers[Rn].value + offset)
                    if with_update:
                        self.registers[Rn] = Value(target_addr.value)
                else:
                    Rn = target_addr_str.strip("[]")
                    target_addr = Address(self.registers[Rn].value)
                if self.__mem_hook is None or self.__mem_hook.ldr is None:
                    self.registers[Rt] = masking[mnemonic](self.memory[target_addr])
                else:
                    self.registers[Rt] = masking[mnemonic](self.__mem_hook.ldr(self, target_addr))
                if Rt == "fp":
                    self.last_fp_ldr_from_addr = target_addr
            elif mnemonic in {"str", "strh", "strb"} and update_flags == False:
                mask = {
                        "str": 0xFFFFFFFF,
                        "strb": 0xFF,
                        "strh": 0xFFFF,
                        }
                Rt, target_addr_str = inst.op_str.split(', ', 1)
                if ',' in target_addr_str:
                    # Assumes pre-indexing only
                    with_update = False
                    if target_addr_str.endswith("!"):
                        # Pre-Indexing with update
                        with_update = True
                        target_addr_str = target_addr_str.strip("!")
                    # Assumes immediate offset only
                    Rn, target_addr_offset_str = target_addr_str.strip("[]").split(', ', 1)
                    offset = int(target_addr_offset_str.strip('#'), 0)
                    target_addr = Address(self.registers[Rn].value + offset)
                    if with_update:
                        self.registers[Rn] = Value(target_addr.value)
                else:
                    Rn = target_addr_str.strip("[]")
                    target_addr = Address(self.registers[Rn].value)
                if self.__mem_hook is None or self.__mem_hook.str is None:
                    self.memory[target_addr] = self.registers[Rt] & mask[mnemonic]
                else:
                    self.__mem_hook.str(self, target_addr, self.registers[Rt] & mask[mnemonic])
            elif mnemonic in {"ldm"} and update_flags == False:
                # Assumes addr_mode = IA only
                Rn, reglist_str = inst.op_str.split(', ', 1)
                reglist = reglist_str.strip('{}').split(', ')
                for reg in reglist:
                    target_addr = Address(self.registers[Rn].value)
                    if self.__mem_hook is None or self.__mem_hook.ldr is None:
                        self.registers[reg] = self.memory[target_addr]
                    else:
                        self.registers[reg] = self.__mem_hook.ldr(self, target_addr)
                    self.registers[Rn] += 4
            elif mnemonic in {"stm"} and update_flags == False:
                # Assumes addr_mode = IA only
                Rn, reglist_str = inst.op_str.split(', ', 1)
                reglist = reglist_str.strip('{}').split(', ')
                for reg in reglist:
                    target_addr = Address(self.registers[Rn].value)
                    if self.__mem_hook is None or self.__mem_hook.str is None:
                        self.memory[target_addr] = self.registers[reg]
                    else:
                        self.__mem_hook.str(self, target_addr, self.registers[reg])
                    self.registers[Rn] += 4
            elif mnemonic in {"add", "sub", "adc", "sbc", "mul", "and", "orr", "eor", "bic", "lsl", "lsr"}:
                Rd, Rn, op2 = inst.op_str.split(', ')
                op1 = self.registers[Rn]
                # Assume op2 is either #imm16 or [Rn]
                if op2.startswith('#'):
                    op2 = Value(int(op2.strip('#'), 0))
                else:
                    op2 = self.registers[op2]
                ops = {
                        "add": lambda a, b: a + b,
                        "sub": lambda a, b: a - b,
                        "adc": lambda a, b: a + b + (1 if self.flags["C"] else 0),
                        "sbc": lambda a, b: a - b - (0 if self.flags["C"] else 1),
                        "mul": lambda a, b: a * b,
                        "and": lambda a, b: a & b,
                        "orr": lambda a, b: a | b,
                        "eor": lambda a, b: a ^ b,
                        "bic": lambda a, b: a & (-b-1),
                        "lsl": lambda a, b: a << b,
                        "lsr": lambda a, b: a >> b,
                        }
                result = ops[mnemonic](op1, op2)
                result_value = ops[mnemonic](op1.value, op2.value)
                result_signed = ops[mnemonic](op1.signed_value, op2.signed_value)
                result_msb = result >> 31
                self.registers[Rd] = result
                if update_flags:
                    if mnemonic in {"add", "sub", "adc", "sbc", "mul"}:
                        self.flags["C"] = True if result != result_value else False
                        self.flags["N"] = True if result_msb == 1 else False
                        self.flags["Z"] = True if result == 0 else False
                        self.flags["V"] = True if result.signed_value != result_signed else False
                    elif mnemonic in {"and", "orr", "eor", "bic"}:
                        # Does not update the C flag because no calculation was
                        # done for op2
                        self.flags["N"] = True if result_msb == 1 else False
                        self.flags["Z"] = True if result == 0 else False
                        # Does not affect the V flag
                    elif mnemonic in {"lsl", "lsr"}:
                        # The C flag is unaffected if the shift value is 0.
                        # Otherwise, the C flag is updated to the last bit
                        # shited out
                        if op2 != 0:
                            if mnemonic == "lsl":
                                self.flags["C"] = True if op1 >> 31 == 1 else False
                            else:
                                self.flags["C"] = True if op1 & 1 == 1 else False
                        self.flags["N"] = True if result_msb == 1 else False
                        self.flags["Z"] = True if result == 0 else False
            elif mnemonic in {"mov", "mvn"}:
                Rd, op2 = inst.op_str.split(', ')
                # Assume op2 is either #imm16 or [Rn]
                if op2.startswith('#'):
                    self.registers[Rd] = Value(int(op2.strip('#'), 0))
                else:
                    self.registers[Rd] = self.registers[op2]
                if mnemonic == "mvn":
                    # Performs a bitwise logical NOT operation on the value
                    self.registers[Rd] = ~self.registers[Rd]
                if update_flags:
                    # Does not update the C flag because no calculation was
                    # done for op2
                    result_msb = self.registers[Rd] >> 31
                    self.flags["N"] = True if result_msb == 1 else False
                    self.flags["Z"] = True if self.registers[Rd] == 0 else False
                    # Does not affect the V flag
            elif mnemonic in {"cmp", "cmn"} and update_flags == False:
                Rn, op2 = inst.op_str.split(', ')
                op1 = self.registers[Rn]
                # Assume op2 is either #imm16 or [Rn]
                if op2.startswith('#'):
                    op2 = Value(int(op2.strip('#'), 0))
                else:
                    op2 = self.registers[op2]
                if mnemonic == "cmp":
                    # CMP is the same as SUBS
                    result = op1 - op2
                    result_value = op1.value - op2.value
                    result_signed = op1.signed_value - op2.signed_value
                else:
                    # CMN is the same as ADDS
                    result = op1 + op2
                    result_value = op1.value + op2.value
                    result_signed = op1.signed_value + op2.signed_value
                result_msb = result >> 31
                self.flags["C"] = True if result != result_value else False
                self.flags["N"] = True if result_msb == 1 else False
                self.flags["Z"] = True if result == 0 else False
                self.flags["V"] = True if result.signed_value != result_signed else False
            elif mnemonic in {"teq", "tst"} and update_flags == False:
                Rn, op2 = inst.op_str.split(', ')
                op1 = self.registers[Rn]
                # Assume op2 is either #imm16 or [Rn]
                if op2.startswith('#'):
                    op2 = Value(int(op2.strip('#'), 0))
                else:
                    op2 = self.registers[op2]
                if mnemonic == "teq":
                    # TEQ is the same as EORS
                    result = op1 ^ op2
                else:
                    # TST is the same as ANDS
                    result = op1 & op2
                result_msb = result >> 31
                # Does not update the C flag because no calculation was
                # done for op2
                self.flags["N"] = True if result_msb == 1 else False
                self.flags["Z"] = True if result == 0 else False
                # Does not affect the V flag
            elif mnemonic in {"b", "bl"}:
                branch_addr = Address(int(inst.op_str.strip('#'), 0))
                if mnemonic == "bl":
                    self.registers["lr"] = Value(addr.value + 4)
                return branch_addr
            else:
                raise Exception("{}: Unknown mnemonic {}".format(addr, inst.mnemonic))

    @property
    def registers(self):
        return self.__registers

    @property
    def flags(self):
        return self.__flags

    @property
    def memory(self):
        return self.__memory
