# 2022 TBTL - Flag checker

Flag checker is a binary that takes user's input from stdin and checks the input against multiple (around 50? big) ifs.

This reverse engineering task was completed **after the competition was finished** with angr. Internal checks done inside the binary are completely unknown to me and the flag content was calculated and dumped completely by angr. Although internal checks are unknown, some small reverse engineering was needed to read out the needed addresses.

In order to get to the flag with angr one needs to setup a `blank_state` on the angr project with the start address of main as `0x4011c3` and `LAZY_SOLVES` option set. The binary is a PIE executable, but angr will load it by default at base address `0x400000`.

Initially I tried using the samples from angr that use the `entry_state` with solver constraints to set flag as printable ASCII but that did not work and the simulation manager ended with 13 deadended states. I suspect that this was due to the overly complex calculations performed by angr which in the end timed out the solver.

The solution that finally worked was setting up the `blank_state` with constraints on flag bytes and setting the flag bitvector to `rbp-0x70` (memory where the input string is stored):
```
001011e9 48 8d 45 90     LEA        RAX=>local_78,[RBP + -0x70]	; input stored here
001011ed 48 89 c6        MOV        RSI,RAX
001011f0 48 8d 05        LEA        RAX,[DAT_00108041]
         4a 6e 00 00
001011f7 48 89 c7        MOV        RDI=>DAT_00108041,RAX	; %73s / fmt
001011fa b8 00 00        MOV        EAX,0x0
         00 00
001011ff e8 5c fe        CALL       <EXTERNAL>::__isoc99_scanf
         ff ff
```

It is important that the state has the `LAZY_SOLVES` option set because that would tell the solver to not search for the solution immediately but to move further down the path to collect more constraints which would in the end simplify the search for the solution.

Here is the bitvector constraints setup and loading of the bitvector to `rbp-0x70`:
```python
INPUT_LEN = 73

# Creates bitvectors of size 8 bits, 73 times (corresponds to flag size in bytes)
flag_bytes = [claripy.BVS("flag_{}".format(i), 8) for i in range(INPUT_LEN)]
flag = claripy.Concat(*flag_bytes)

# Add initial bytes to solver constraints, must be equals
content = b"TBTL{"
for i in range(len(content)):
	st.solver.add(flag_bytes[i] == content[i])

# Add flag content between brackets as printable ASCII
for i in flag_bytes[len(content):-1]:
	st.solver.add(i <= 0x7f)
	st.solver.add(i >= 0x20)

# Last character is always '}'
st.solver.add(flag_bytes[-1] == 0x7d)

# Load the bitvector to rbp-0x70
for i in range(INPUT_LEN):
	st.memory.store(st.regs.rbp-0x70+i, flag_bytes[i])
```

When this is done, all that we need is to run the angr explorer to find the address `0x40732a` as this address is the start of the block that prints out `Correct!` message (the addresses are displayed below as `0x0010732a` since Ghidra loads the binary at base address `0x00100000`):
```
0010732a 48 8d 05        LEA        RAX,[s_Correct!_00108052]		= "Correct!\n"
         21 0d 00 00
00107331 48 89 c7        MOV        RDI=>s_Correct!_00108052,RAX	= "Correct!\n"
00107334 e8 40 9e        CALL       pretty_print
         ff ff
00107339 b8 00 00        MOV        EAX,0x0
         00 00
```

We add the explore part and dump all possible flag combinations:
```python
sm = p.factory.simulation_manager(st)
sm.explore(find=0x40732a)

for i in sm.found:
	print(i.posix.dumps(0))
```

When executed only one path is found:
```
$ python3 solve_2022_tbtl_flag_checker.py 
WARNING | 2022-05-15 22:03:23,768 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
< ... >
WARNING | 2022-05-15 22:04:07,312 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV64 mem_7ffffffffff0000_116_64{UNINITIALIZED}>
b'TBTL{S0lv1ng_4_Sy5t3m_0f_Equ4710n5_15_3a5y_Wh3n_Y0u_H4v3_7h3_R1gh7_70015}'
```

Solution code is in `solve_2022_tbtl_flag_checker.py`

In the end, after a few more tests it seems that none of the constraints or flag memory storing is needed since plain `blank_state` also works and prints the flag under a minute:
```python
>>> p = angr.Project("flag_checker")
WARNING | 2022-05-15 22:24:48,192 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
>>> st = p.factory.blank_state(addr=0x4011c3, add_options={angr.options.LAZY_SOLVES})
>>> sm = p.factory.simulation_manager(st)
>>> sm.explore(find=0x40732a)
WARNING | 2022-05-15 22:24:59,962 | angr.storage.memory_mixins.default_filler_mixin | Filling register rbp with 8 unconstrained bytes referenced from 0x4011c3 (main+0x0 in flag_checker (0x11c3))
WARNING | 2022-05-15 22:25:43,081 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7ffffffffff0000 with 8 unconstrained bytes referenced from 0x407353 (main+0x6190 in flag_checker (0x7353))
WARNING | 2022-05-15 22:25:46,561 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV64 mem_7ffffffffff0000_1119_64{UNINITIALIZED}>
WARNING | 2022-05-15 22:25:47,431 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7ffffffffff0000 with 8 unconstrained bytes referenced from 0x407353 (main+0x6190 in flag_checker (0x7353))
WARNING | 2022-05-15 22:25:51,464 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV64 mem_7ffffffffff0000_1120_64{UNINITIALIZED}>
<SimulationManager with 71 active, 2 unconstrained, 1 found>
>>> sm.found[0].posix.dumps(0)
b'TBTL{S0lv1ng_4_Sy5t3m_0f_Equ4710n5_15_3a5y_Wh3n_Y0u_H4v3_7h3_R1gh7_70015}'
```
