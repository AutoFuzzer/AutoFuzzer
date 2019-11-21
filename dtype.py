#!/usr/bin/env python3

class Value(object):
    def __init__(self, value=0, bit=32):
        # Check bit size
        try:
            bit = int(bit)
            if bit <= 0:
                raise ValueError
        except ValueError:
            raise ValueError("Invalid bit size: {}".format(bit))
        # Copy if argument is an object of the same class
        if isinstance(value, self.__class__):
            value = value.value
        self.__bit = bit
        self.value = value

    @property
    def value(self):
        return self.__value

    @property
    def signed_value(self):
        if self.__value < 2 ** (self.bit - 1):
            return self.__value
        else:
            return self.__value - 2 ** self.bit

    @value.setter
    def value(self, value):
        # Validate argument type
        try:
            value = int(value)
        except ValueError:
            raise ValueError("Invalid value: {}".format(value))
        self.__value = value % 2**self.bit

    @property
    def bit(self):
        return self.__bit

    @bit.setter
    def bit(self, bit):
        self.__bit = bit
        self.value = self.value

    def __str__(self):
        formatter = "0x{:0" + str(self.bit // 4) + "X}"
        return formatter.format(self.value)

    def __repr__(self):
        return "{}({})".format(self.__class__.__name__, self.__str__())

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.value == other.value
        else:
            return self.__value == other

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        if isinstance(other, self.__class__):
            return self.value < other.value
        else:
            return self.value < other

    def __le__(self, other):
        if isinstance(other, self.__class__):
            return self.value <= other.value
        else:
            return self.value <= other

    def __gt__(self, other):
        if isinstance(other, self.__class__):
            return self.value > other.value
        else:
            return self.value > other

    def __ge__(self, other):
        if isinstance(other, self.__class__):
            return self.value >= other.value
        else:
            return self.value >= other

    def __add__(self, other):
        if isinstance(other, self.__class__):
            return self.__class__(self.value + other.value, bit=self.bit)
        return self.__class__(self.value + other, bit=self.bit)

    def __sub__(self, other):
        if isinstance(other, self.__class__):
            return self.__class__(self.value - other.value, bit=self.bit)
        return self.__class__(self.value - other, bit=self.bit)

    def __mul__(self, other):
        if isinstance(other, self.__class__):
            return self.__class__(self.value * other.value, bit=self.bit)
        return self.__class__(self.value * other, bit=self.bit)

    def __mod__(self, other):
        if isinstance(other, self.__class__):
            return self.__class__(self.value % other.value, bit=self.bit)
        return self.__class__(self.value % other, bit=self.bit)

    def __lshift__(self, other):
        if isinstance(other, self.__class__):
            return self.__class__(self.value << other.value, bit=self.bit)
        return self.__class__(self.value << other, bit=self.bit)

    def __rshift__(self, other):
        if isinstance(other, self.__class__):
            return self.__class__(self.value >> other.value, bit=self.bit)
        return self.__class__(self.value >> other, bit=self.bit)

    def __and__(self, other):
        if isinstance(other, self.__class__):
            return self.__class__(self.value & other.value, bit=self.bit)
        return self.__class__(self.value & other, bit=self.bit)

    def __or__(self, other):
        if isinstance(other, self.__class__):
            return self.__class__(self.value | other.value, bit=self.bit)
        return self.__class__(self.value | other, bit=self.bit)

    def __xor__(self, other):
        if isinstance(other, self.__class__):
            return self.__class__(self.value ^ other.value, bit=self.bit)
        return self.__class__(self.value ^ other, bit=self.bit)

    def __invert__(self):
        return self.__class__(-self.value - 1, bit=self.bit)

    def __neg__(self):
        return self.__class__(-self.value)

class Address(Value):
    pass

class SortedDict(dict):
    def __str__(self):
        return " ".join(["{}: {}".format(
            key, self[key]) for key in sorted(self)])

    def __repr__(self):
        return str(self)

    def copy(self):
        new = self.__class__()
        for key, value in self.items():
            new[key] = value
        return new

class SortedInput(SortedDict):
    def __str__(self):
        return " ".join(["%IX{}: {}".format(
            key, self[key]) for key in sorted(self)])

class SortedOutput(SortedDict):
    def __str__(self):
        return " ".join(["%QX{}: {}".format(
            key, self[key]) for key in sorted(self)])

class SortedValue(SortedDict):
    def __str__(self):
        return " ".join(["{}: {}".format(
            key, self[key].value) for key in sorted(self)])
