from collections import defaultdict, Counter
import json
import os.path as op

import ida_strlist
import ida_funcs
import idautils
import idc
import idaapi


CWD = op.dirname(__file__)

# Rebuild the string list to make sure it's up to date.
ida_strlist.build_strlist()

function_string_references = defaultdict(lambda: [])
string_refcounts = {}
# All the xrefs for each function.
function_xrefs: dict[int, set[int]] = defaultdict(lambda: Counter())
# The functions that are referenced within each function.
included_function_xrefs: dict[int, set[int]] = defaultdict(lambda: Counter())
# NOTE: If the function has no to or from xrefs then it won't be included.

named = False

# First, generate the function xref maps
print("Generating function xref maps")
ea = idaapi.get_imagebase()
while ea != idaapi.BADADDR:
    next_func = ida_funcs.get_next_func(ea)
    if not next_func:
        break
    ea = next_func.start_ea
    func_name = idc.get_func_name(ea)
    for xref in idautils.CodeRefsTo(ea, 1):
        # xref_func_ea = ida_funcs.get_func(xref).start_ea  # the ea of the actual function that xref's it
        xref_func_name = idc.get_func_name(xref)
        function_xrefs[func_name][xref_func_name] += 1
        included_function_xrefs[xref_func_name][func_name] += 1

# Now, go over the string list, get the xrefs to each string and build up a mapping.
print("Generating string xref maps")
string_count = ida_strlist.get_strlist_qty()
string_info = ida_strlist.string_info_t()
for i in range(string_count):
    ida_strlist.get_strlist_item(string_info, i)
    ea = string_info.ea
    str_val = idc.get_strlit_contents(ea).decode()
    xrefs = list(idautils.XrefsTo(ea, 0))
    string_refcounts[str_val] = len(xrefs)
    for xref in xrefs:
        frm = xref.frm
        func_name = idc.get_func_name(frm)
        # func_start_ea = ida_funcs.get_func(frm).start_ea
        if func_name:
            function_string_references[func_name].append(str_val)

print("Dumping string refcounts")
with open(op.join(CWD, "string_refcounts.json"), "w") as f:
    json.dump(string_refcounts, f, indent=1)

print("Dumping function string references")
if named:
    prefix = "named_"
else:
    prefix = "unnamed_"

with open(op.join(CWD, "data", prefix + "function_string_references.json"), "w") as f:
    json.dump(function_string_references, f, indent=1)

print("Dumping func xref counts")
with open(op.join(CWD, "data", prefix + "func_callers.json"), "w") as f:
    json.dump(function_xrefs, f, indent=1)
with open(op.join(CWD, "data", prefix + "func_callees.json"), "w") as f:
    json.dump(included_function_xrefs, f, indent=1)

print("Done")
