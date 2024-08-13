from collections import Counter
import json
import os.path as op
import time


CWD = op.dirname(__file__)
# TEXT = ida_segment.get_segm_by_name(".text")

XREF_REPEATS = 10


class HashedCounter(Counter):
    def __hash__(self):
        return hash(frozenset(self.items()))
    
    def __le__(self, other: "HashedCounter"):
        keys = set(self.keys())
        if keys <= set(other.keys()):
            for key in keys:
                if self[key] > other.get(key, 0):
                    return False
            return True
        return False


# Load the "DB"s
with open(op.join(CWD, "data", "unnamed_function_string_references.json"), "r") as f:
    _unnamed_function_string_references = json.load(f)

# First, remove all the non-unique functions since we won't be able to match these.

unnamed_function_string_references = {}
for key, value in _unnamed_function_string_references.items():
    unnamed_function_string_references[HashedCounter(value)] = key
unnamed_func_counts = HashedCounter(list(unnamed_function_string_references.keys()))
# Remove all the non-unique ones since we don't care about them...
to_remove = set()
for key, count in unnamed_func_counts.items():
    if count != 1:
        to_remove.add(key)
for key in to_remove:
    unnamed_func_counts.pop(key)

with open(op.join(CWD, "data", "named_function_string_references.json"), "r") as f:
    _named_function_string_references = json.load(f)

named_function_string_references = {}
for key, value in _named_function_string_references.items():
    named_function_string_references[HashedCounter(value)] = key
named_func_counts = HashedCounter(list(named_function_string_references.keys()))
# Remove all the non-unique ones since we don't care about them...
to_remove = set()
for key, count in named_func_counts.items():
    if count != 1:
        to_remove.add(key)
for key in to_remove:
    named_func_counts.pop(key)

### Compare the information.
# First pass: Look for data that matches perfectly.

matches = {}
to_remove = set()

t1 = time.time()

for str_info, count in named_func_counts.items():
    if count == 1 and unnamed_func_counts.get(str_info) == 1:
        matches[unnamed_function_string_references[str_info]] = named_function_string_references[str_info]
        to_remove.add(str_info)

t2 = time.time()

print(f"Found {len(matches)} matches in {t2 - t2:03}s")

for name in to_remove:
    named_func_counts.pop(name)
    unnamed_func_counts.pop(name)

# Second pass:
# Go over all the named ones which have a count of 1 and see if it's a subset of
# an unanmed one.

t1 = time.time()

second_matches = {}
for str_info, count in named_func_counts.items():
    options = []
    if count == 1:
        for u_str_info, u_count in unnamed_func_counts.items():
            if u_count == 1 and str_info <= u_str_info:
                options.append(u_str_info)
    if len(options) == 1:
        second_matches[unnamed_function_string_references[options[0]]] = named_function_string_references[str_info]
        unnamed_func_counts.pop(options[0])

with open(op.join(CWD, "output", "subset_matched.txt"), "w") as f:
    for k, v in second_matches.items():
        f.write(f"{k}\t{v}\n")

t2 = time.time()

print(f"Found {len(second_matches)} subset matches in {t2 - t1:03}s")

# Merge the second matches into the first to make the next analysis easier...
matches.update(second_matches)

# Third pass:
# Read in the function xref information and use this to try and build up new function names based on the
# functions which reference the named ones, or the functions referenced in them.

# This is the list of functions which get called within the given function
with open(op.join(CWD, "data", "named_func_callees.json"), "r") as f:
    _named_func_callees = json.load(f)
with open(op.join(CWD, "data", "unnamed_func_callees.json"), "r") as f:
    _unnamed_func_callees = json.load(f)
# This is the list of functions which call the given function.
with open(op.join(CWD, "data", "named_func_callers.json"), "r") as f:
    _named_func_callers = json.load(f)
with open(op.join(CWD, "data", "unnamed_func_callers.json"), "r") as f:
    _unnamed_func_callers = json.load(f)

# Go over the mapping between unknown and known function names.
# Do a lookup of the unknown name in the caller and callee graph. If there is a single unknown value in it,
# then compare it to the known graph and add the name.

for i in range(XREF_REPEATS):
    third_matches = {}

    t1 = time.time()

    for unknown, known in matches.items():
        if not unknown:
            continue
        repeated_names = set()
        unknown_ref_to_function_names = list(_unnamed_func_callees.get(unknown, {}).keys())
        known_ref_to_function_names = list(_named_func_callees.get(known, {}).keys())
        # Check if both callee sets are just one element (for simplicity).
        if len(unknown_ref_to_function_names) == 1 and len(known_ref_to_function_names) == 1:
            kf = known_ref_to_function_names[0]
            ukf = unknown_ref_to_function_names[0]
            # If the ref'd function isn't already known, add it.
            if kf in third_matches:
                repeated_names.add(kf)
            if ukf not in matches:
                third_matches[kf] = ukf

        # Same analysis for the function callers
        repeated_names = set()
        unknown_ref_from_function_names = list(_unnamed_func_callers.get(unknown, {}).keys())
        known_ref_from_function_names = list(_named_func_callers.get(known, {}).keys())
        # Check if both callee sets are just one element (for simplicity).
        if len(unknown_ref_from_function_names) == 1 and len(known_ref_from_function_names) == 1:
            # If the ref'd function isn't already known, add it.
            kf = known_ref_from_function_names[0]
            ukf = unknown_ref_from_function_names[0]
            if kf in third_matches:
                repeated_names.add(kf)
            if ukf not in matches:
                third_matches[kf] = ukf

        # Sometimes if functions are changed they can be determined incorrectly. In this case, remove the ambiguities.
        for name in repeated_names:
            del third_matches[name]

    matches.update({ukf: kf for kf, ukf in third_matches.items()})

    t2 = time.time()

    print(f"[Round {i}] Found {len(third_matches)} function xref matches in {t2 - t1:03}s")

with open(op.join(CWD, "output", "func_xref_matched.txt"), "w") as f:
    for k, v in third_matches.items():
        f.write(f"{v}\t{k}\n")

# De-dupe values over the entire thing.
repeated = Counter(matches.values())
repeated = [x for x in repeated if repeated[x] > 1]
to_delete = [x for x in matches if matches[x] in repeated]
for rep in to_delete:
    del matches[rep]


with open(op.join(CWD, "output", "matched.txt"), "w") as f:
    for k, v in matches.items():
        f.write(f"{k}\t{v}\n")

print(f"Total functions named: {len(matches)}")
