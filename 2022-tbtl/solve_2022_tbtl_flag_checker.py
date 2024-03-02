import angr
import claripy
import string

INPUT_LEN = 73

p = angr.Project("flag_checker")
st = p.factory.blank_state(addr=0x4011c3, add_options={angr.options.LAZY_SOLVES})
flag_bytes = [claripy.BVS("flag_{}".format(i), 8) for i in range(INPUT_LEN)]
flag = claripy.Concat(*flag_bytes)

content = b"TBTL{"
for i in range(len(content)):
	st.solver.add(flag_bytes[i] == content[i])

for i in flag_bytes[len(content):-1]:
	st.solver.add(i <= 0x7f)
	st.solver.add(i >= 0x20)

st.solver.add(flag_bytes[-1] == 0x7d)

for i in range(INPUT_LEN):
	st.memory.store(st.regs.rbp-0x70+i, flag_bytes[i])

sm = p.factory.simulation_manager(st)
sm.explore(find=0x40732a)

for i in sm.found:
	print(i.posix.dumps(0))
