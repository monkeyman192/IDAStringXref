import os.path as op
from collections import Counter

CWD = op.dirname(__file__)

values = []

with open(op.join(CWD, "output", "matched.txt"), "r") as f:
    for i, line in enumerate(f):
        _split = line.strip().split()
        try:
            values.append(_split[1])
        except:
            print(f"Error on line {i}")

data = Counter(values)
res = [x for x in data if data[x] > 1]
if res:
    print(f"OH NO! There are {len(res)} repeated values!")
