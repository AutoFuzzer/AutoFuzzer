Subroutine explanation:
0-1: same
2-3: different (due to address being called)
4-24: same (16 is same as 21)
25: different (PLC program logic)
25+1-25+n: differnt
    - The order of FB subroutines depend on the order of appearance in VAR
      section
    - The order is also the same as the order of ascendingly sorted calling
      address (and the addresses which store these addresses) in the PLC
      program subroutine
    - In the header metadata of each subroutine stores the address which the
      subroutine is loaded to
Header length depends on the project structure (e.g., GVL)
Number of types of FBs used is n
PLC program subroutine is the 26th subroutine
Constant subroutine is the 112+5n subroutine (or the 8th last subroutine).
    - This subroutine also initializes all the outputs and internal variables
Subroutine jumping table is the 118+5n subroutine (or the 2nd last subroutine)
The total number of subroutines is 119+5n.

Subroutine:
    - Each subroutine has a 20 bytes header:
        - 0-3: unknown, seems to be related to the length of the subroutine
        - 4-7: 0x00040621 (magic number)
        - 8-11: loading address of the subroutine in the memory
        - 12-15: unknown, seems to be related to the length of the subroutine
        - 16-19: total length of the subroutine, including the data section,
          excluding the header
    - Usually following the header, there is the code section, then the data
      section (if any)
    - For very long subroutines, the code section may be broken down and
      inserted with data section in the middle.
        - Immediately before the inserted data section is an unconditional
          branching instruction "b label". However, the reverse is not true.
        - To address this issue, the entire disassembly is scanned and all
          branches are explored to maximize the code coverage. Those lines that
          are never covered are reverted to the Decoded type from Instruction
          type
        - TODO: If the same %QX or %IX is accessed in both parts of the code,
          the addresses will be stored in both data sections after each code
          section. This will cause an ambiguity and lead to I/O write
          collision when analyzing the disassembly

Program Subroutine:
    - Input (%IX) and output (%QX) registers are referenced with their index,
      e.g., %IX0 is referenced using 0x00000000.
    - This may cause confusion while parsing, e.g., %IX0 and %QX0 are both
      0x00000000
    - A simple but effective heuristic is to check whether the address
      (accessed through fp) has been written to. The assumption is that only
      %QX can be written.
    - TODO: An exception is %MX, which are memory registers that can be both
      read and written. There is no solution for it so far.
    - TODO: A special case is that sometimes the address holding the variables
      is not loaded directly from the program data section, but rather via
      computation. For example, fp could be %IX0 which is 0x00000000. Accessing
      to %IX1 could be achieved via [fp, #1]. This is hard to track as the
      index (0, 1, etc.) is not stored in the data section and hence cannot be
      tracked via the address.
    - Internal variables and function block data structures are referenced with
      address, e.g., 0x123.
    - A heuristic is used to distinguish internal variables from I/O variables,
      i.e., anything less than 0x10 is considered as I/O variables

Function Block:
    - All function blocks (FBs) start with "sub sp, sp, #4", and ends with "add
      sp, sp, #4"
    - All non-function block (NFB) statements starts with "ldr fp, [pc, #0x]"
      and ends with "strb rn, [fp]" or "strb rn, [fp, #0x]"
    - NFBs could also start with "ldrb rn, [fp, #0x]" when fp doesn't need to
      be loaded again
    - TODO: Additional FBs such as type conversion need to be decoded

Function block memory footprint:
R_TRIG
  .CLK (1B): 0x4
  .Q (1B): 0x5
F_TRIG
  .CLK (1B): 0x4
  .Q (1B): 0x5
SR
  .SET1 (1B): 0x4
  .RESET (1B): 0x5
  .Q1 (1B): 0x6
RS
  .SET (1B): 0x4
  .RESET1 (1B): 0x5
  .Q1 (1B): 0x6
TP
  .IN (1B): 0x4
  .PT (4B): 0x8
  .Q (1B): 0xc
  .ET (4B): 0x10
TON
  .IN (1B): 0x4
  .PT (4B): 0x8
  .Q (1B): 0xc
  .ET (4B): 0x10
TOF
  .IN (1B): 0x4
  .PT (4B): 0x8
  .Q (1B): 0xc
  .ET (4B): 0x10
CTU
  .CU (1B): 0x4
  .RESET (1B): 0x5
  .PV (2B): 0x6
  .Q (1B): 0x8
  .CV (2B): ??
CTD
  .CD (1B): 0x4
  .LOAD (1B): 0x5
  .PV (2B): 0x6
  .Q (1B): 0x8
  .CV (2B): ??
