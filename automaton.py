#!/usr/bin/env python3
from collections import defaultdict

from dtype import *

class State(object):
    def __init__(self, from_str=None):
        self.outputs = SortedOutput()
        self.internal_vars = SortedDict()
        self.function_block_states = SortedDict()
        if from_str:
            try:
                # mode can be QX, IV, FBS
                # QX: output
                # IV: internal variable
                # FBS: function block state
                mode = None
                index = None
                addr = None
                symbol = None
                states = None
                for sub_str in from_str.split(' '):
                    if len(sub_str) == 0:
                        continue
                    if mode is None and sub_str.endswith(":"):
                        if sub_str.startswith("%QX"):
                            mode = "QX"
                            index = int(sub_str.strip("%QX:"))
                        elif sub_str.startswith("0x"):
                            mode = "IV"
                            addr = Address(int(sub_str.strip(":"), 0))
                        elif sub_str.startswith((
                            "R_TRIG",
                            "F_TRIG",
                            "SR",
                            "RS",
                            "TP",
                            "TON",
                            "TOF",
                            "CTU",
                            "CTD"
                            )):
                            mode = "FBS"
                            symbol = sub_str.strip(":")
                        else:
                            raise
                    elif mode == "QX" and sub_str.startswith("0x") and not sub_str.endswith(":"):
                        value = Value(int(sub_str, 0))
                        if index is not None:
                            self.outputs[index] = value
                        else:
                            raise
                        index = None
                        mode = None
                    elif mode == "IV" and sub_str.startswith("0x") and not sub_str.endswith(":"):
                        value = Value(int(sub_str, 0))
                        if addr is not None:
                            self.internal_vars[addr] = value
                        else:
                            raise
                        addr = None
                        mode = None
                    elif mode == "FBS" and not sub_str.endswith(":"):
                        if sub_str in {"True", "False"}:
                            state = True if sub_str == "True" else False
                            if symbol is not None:
                                self.function_block_states[symbol] = state
                            symbol = None
                            mode = None
                        elif sub_str.strip("(),") in {"True", "False"}:
                            if states is None:
                                if sub_str.startswith("(") and sub_str.endswith(","):
                                    state = True if sub_str.strip("(),") == "True" else False
                                    states = [state]
                                else:
                                    raise
                            else:
                                if sub_str.endswith(","):
                                    state = True if sub_str.strip("(),") == "True" else False
                                    states.append(state)
                                elif sub_str.endswith(")"):
                                    state = True if sub_str.strip("(),") == "True" else False
                                    states.append(state)
                                    if symbol is not None:
                                        self.function_block_states[symbol] = tuple(states)
                                    else:
                                        raise
                                    states = None
                                    symbol = None
                                    mode = None
                        else:
                            raise
                    else:
                        raise
            except:
                raise Exception("Cannot parse string {} into {}".format(from_str, self.__class__.__name__))

    def __str__(self):
        return " ".join([str(self.outputs), str(self.internal_vars), str(self.function_block_states)])

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        if self.outputs != other.outputs:
            return False
        if self.internal_vars != other.internal_vars:
            return False
        if self.function_block_states != other.function_block_states:
            return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def copy(self):
        new = self.__class__()
        new.outputs = self.outputs.copy()
        new.internal_vars = self.internal_vars.copy()
        new.function_block_states = self.function_block_states.copy()
        return new

class Transition(object):
    def __init__(self, from_str=None):
        self.inputs = SortedInput()
        self.timers = SortedValue()
        self.counters = SortedValue()
        if from_str:
            try:
                # mode can be IX, T, CT
                # IX: input
                # T: timer
                # CT: counter
                mode = None
                index = None
                symbol = None
                for sub_str in from_str.split(' '):
                    if len(sub_str) == 0:
                        continue
                    if mode is None and sub_str.endswith(":"):
                        if sub_str.startswith("%IX"):
                            mode = "IX"
                            index = int(sub_str.strip("%IX:"))
                        elif sub_str.startswith("T"):
                            mode = "T"
                            symbol = sub_str.strip(":")
                        elif sub_str.startswith("CT"):
                            mode = "CT"
                            symbol = sub_str.strip(":")
                    elif mode == "IX" and sub_str.startswith("0x") and not sub_str.endswith(":"):
                        value = Value(int(sub_str, 0))
                        if index is not None:
                            self.inputs[index] = value
                        else:
                            raise
                        index = None
                        mode = None
                    elif mode == "T" and sub_str.isdigit() and not sub_str.endswith(":"):
                        value = Value(int(sub_str, 0))
                        if symbol is not None:
                            self.timers[symbol] = value
                        else:
                            raise
                        symbol = None
                        mode = None
                    elif mode == "CT" and sub_str.isdigit() and not sub_str.endswith(":"):
                        value = Value(int(sub_str, 0))
                        if symbol is not None:
                            self.counters[symbol] = value
                        else:
                            raise
                        symbol = None
                        mode = None
                    else:
                        raise
            except:
                raise Exception("Cannot parse string {} into {}".format(from_str, self.__class__.__name__))

    def __str__(self):
        return " ".join([str(self.inputs), str(self.timers), str(self.counters)])

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        if self.inputs != other.inputs:
            return False
        if self.timers != other.timers:
            return False
        if self.counters != other.counters:
            return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def copy(self):
        new = self.__class__()
        new.inputs = self.inputs.copy()
        new.timers = self.timers.copy()
        new.counters = self.counters.copy()
        return new

class Automaton(object):
    def __init__(self, fromfile=None):
        self.__states = set()
        self.__states_lut = {}
        self.__graph = defaultdict(dict)
        if fromfile:
            filename=fromfile
            if "." in filename:
                fmt = filename.rsplit('.', 1)[-1]
            else:
                raise TypeError("Unspecified file format")
            if fmt == "gdf":
                with open(filename) as f:
                    line = f.readline().strip()    # Node list header
                    if not line.startswith("nodedef"):
                        raise Exception("File corrupted: {}".format(filename))
                    while True:
                        line = f.readline().strip()
                        if line.startswith("edgedef"):
                            # Edge list header
                            elements_compound = [e.strip() for e in line.strip("edgedef>").split(',')]
                            elements = [e.split(' ')[0] for e in elements_compound]
                            elements_type = {e.split(' ')[0]: e.split(' ')[1]
                                    for e in elements_compound}
                            break
                        elif len(line) == 0:
                            raise Exception("File corrupted: {}".format(filename))
                        else:
                            state = State(line)
                            self.states.add(state)
                            self.__states_lut[str(state)] = state
                    while True:
                        line = f.readline().strip()
                        if len(line) == 0:
                            break
                        # Parse edgedef
                        columns = line.split(',')
                        if len(columns) != len(elements):
                            raise Exception("File corrupted: {}".format(filename))
                        if "label" in elements:
                            label = Transition(columns[elements.index("label")])
                        else:
                            label = None
                        node1 = State(columns[elements.index("node1")])
                        node2 = State(columns[elements.index("node2")])
                        if node1 not in self.states or node2 not in self.states:
                            raise Exception("File corrupted: {}".format(filename))
                        self.add(node1, label, node2)
            elif fmt == "gml":
                with open(filename) as f:
                    index_state = {}
                    in_node = False
                    in_edge = False
                    node_id = None
                    source = None
                    target = None
                    for line in f:
                        line = line.strip()
                        if not in_node and not in_edge:
                            if line.startswith("node ["):
                                in_node = True
                            elif line.startswith("edge ["):
                                in_edge = True
                        elif in_node:
                            if line.startswith("id"):
                                if node_id is None:
                                    node_id = line.split(" ", 1)[1]
                                else:
                                    raise Exception("File corrupted: {}".format(filename))
                            elif line.startswith("label"):
                                if node_id is None:
                                    raise Exception("File corrupted: {}".format(filename))
                                else:
                                    state_str = line.split(" ", 1)[1].strip('"')
                                    index_state[node_id] = state_str
                                    state = State(state_str)
                                    self.states.add(state)
                                    self.__states_lut[str(state)] = state
                                    node_id = None
                            elif line == ']':
                                in_node = False
                        elif in_edge:
                            if line.startswith("source"):
                                if source is None:
                                    source = line.split(" ", 1)[1]
                                    if source not in index_state:
                                        raise Exception("File corrupted: {}".format(filename))
                                else:
                                    raise Exception("File corrupted: {}".format(filename))
                            elif line.startswith("target"):
                                if target is None:
                                    target = line.split(" ", 1)[1]
                                    if target not in index_state:
                                        raise Exception("File corrupted: {}".format(filename))
                                else:
                                    raise Exception("File corrupted: {}".format(filename))
                            elif line.startswith("label"):
                                if source is None or target is None:
                                    raise Exception("File corrupted: {}".format(filename))
                                else:
                                    label = line.split(" ", 1)[1].strip('"')
                                    transition = Transition(label)
                                    self.add(State(index_state[source]), transition, State(index_state[target]))
                                    source = None
                                    target = None
                            elif line == ']':
                                in_edge = False
                        else:
                            raise Exception("File corrupted: {}".format(filename))
            else:
                raise TypeError("Unknown file format: {}".format(fmt))

    def __len__(self):
        return len(self.states)

    def __contains__(self, other):
        if isinstance(other, State):
            return other in self.states
        return False

    def __getitem__(self, key):
        return self.graph[key]

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            if self.states != other.states:
                return False
            if self.graph != other.graph:
                return False
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def states(self):
        return self.__states

    @property
    def graph(self):
        return self.__graph

    @property
    def n_states(self):
        return len(self.states)

    @property
    def n_transitions(self):
        n = 0
        for state1 in self.graph.keys():
            n += len(self[state1])
        return n

    def add(self, state1, condition, state2):
        # Reuse the existing object to save memory
        if state1 in self.states:
            state1 = self.__states_lut[str(state1)]
        if state2 in self.states:
            state2 = self.__states_lut[str(state2)]
        self.graph[state1][condition] = state2
        self.states.add(state1)
        self.__states_lut[str(state1)] = state1
        self.states.add(state2)
        self.__states_lut[str(state2)] = state2

    def intersection(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError
        result = self.__class__()
        for state1 in self.states:
            if state1 in other:
                for condition, state2 in self[state1].items():
                    if condition in other[state1] and state2 == other[state1][condition]:
                        result.add(state1, condition, state2)
        return result

    def __and__(self, other):
        return self.intersection(other)

    def jaccard(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError
        numerator = 0
        denominator = 0
        for state1 in self.states:
            denominator += len(self[state1])
            if state1 in other:
                for condition, state2 in self[state1].items():
                    if condition in other[state1] and state2 == other[state1][condition]:
                        numerator += 1
        for state1 in other.states():
            if state1 in self:
                for condition, state2 in self[state1].items():
                    if condition not in self[state1] or state2 != self[state1][condition]:
                        denominator += 1
            else:
                denominator += len(other[state1])
        return float(numerator) / float(denominator)

    def export(self, filename=None, fmt="gdf"):
        if filename is None:
            filename = "graph." + fmt
        fmt = filename.rsplit(".", 1)[-1]
        if fmt == "gdf":
            with open(filename, 'w') as f:
                f.write("nodedef>name VARCHAR\n")
                for state in self.states:
                    f.write(str(state) + '\n')
                f.write("edgedef>node1 VARCHAR, node2 VARCHAR, directed BOOLEAN, label VARCHAR\n")
                for state1, transitions in self.graph.items():
                    for condition, state2 in transitions.items():
                        f.write(",".join([str(state1), str(state2), "true", str(condition)]) + '\n')
        elif fmt == "gml":
            with open(filename, 'w') as f:
                f.write("graph [\n")
                f.write("  directed 1\n")
                f.write("  multigraph 1\n")
                # Encode the state into an index
                state_index = {}
                for state in self.states:
                    state_index[state] = len(state_index)
                    f.write("  node [\n")
                    f.write("    id {}\n".format(state_index[state]))
                    f.write("    label \"{}\"\n".format(str(state)))
                    f.write("  ]\n")
                for state1, transitions in self.graph.items():
                    for condition, state2 in transitions.items():
                        f.write("  edge [\n")
                        f.write("    source {}\n".format(state_index[state1]))
                        f.write("    target {}\n".format(state_index[state2]))
                        f.write("    label \"{}\"\n".format(str(condition)))
                        f.write("  ]\n")
                f.write("]\n")
        else:
            raise TypeError("Unknown file format: {}".format(fmt))
