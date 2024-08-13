import os.path as op

import ida_name

CWD = op.dirname(__file__)

matched = []
with open(op.join(CWD, "matched.txt"), "r") as f:
    for line in f:
        _split = line.strip().split()
        if _split[0].startswith("sub_") and not _split[1].startswith("sub_"):
            addr = _split[0][4:]
            matched.append((int(addr, 16), _split[1]))

for addr, name in matched:
    ida_name.set_name(addr, name, ida_name.SN_FORCE)

print(f"Renamed {len(matched)} functions")