# Simple script by monkeyman192 to find lots of strings which don't have xrefs
# in IDA and add them.

from ida_xref import XREF_USER, dr_O

BASE = 0x140000000
RDATA = ida_segment.get_segm_by_name(".rdata")
TEXT = ida_segment.get_segm_by_name(".text")


def is_in_rdata(ea):
    return RDATA.start_ea <= ea <= RDATA.end_ea


def create_xref(from_ea, to_ea) -> bool:
    return ida_xref.add_dref(from_ea, to_ea, XREF_USER | dr_O)


count = 0


start_bytes = (
    "0F B6 84 12",
    "0F B6 84 1A",
    "0F B6 94 11",
    "0F B6 94 19",
    "0F B6 94 21",
    "0F B6 94 29",
    "0F B6 94 30",
    "0F B6 94 38",
    "0F B6 94 31",
    "0F B6 94 39",
    "0F B6 8C 02",
    "0F B6 8C 0A",
    "0F B6 8C 12",
    "0F B6 8C 1A",
    "0F B6 8C 22",
    "0F B6 8C 2A",
    "0F B6 8C 32",
    "0F B6 8C 3A",
    "0F B6 84 32",
    "0F B6 84 3A",
    "41 0F B6 94 30",
    "41 0F B6 94 38",
    "42 0F B6 94 31",
    "42 0F B6 94 39",
    "42 0F B6 8C 02",
    "42 0F B6 8C 0A",
    "42 0F B6 8C 12",
    "42 0F B6 8C 1A",
    "41 0F B6 8C 1A",
    "42 0F B6 8C 22",
    "42 0F B6 8C 2A",
    "42 0F B6 8C 32",
    "42 0F B6 8C 3A",
    "42 0F B6 94 11",
    "42 0F B6 94 19",
    "42 0F B6 94 21",
    "42 0F B6 94 29",
    "44 0F B6 84 12",
    "44 0F B6 84 1A",
    "46 0F B6 84 12",
    "46 0F B6 84 1A",
    "46 0F B6 84 32",
    "46 0F B6 84 3A",
)
140560580

def is_head(ea):
    return ea == idc.prev_head(idc.next_head(ea))


def get_binary_results(search_str: str):
    start = TEXT.start_ea
    end = TEXT.end_ea
    curr = start - 1
    addrs = []
    while curr < end:
        addr = ida_search.find_binary(
            curr + 1,
            end,
            search_str,
            16,
            idc.SEARCH_NEXT | idc.SEARCH_DOWN
        )
        if addr == 0xFFFFFFFFFFFFFFFF:
            return addrs
        else:
            if is_head(addr):
                addrs.append(addr)
            curr = addr


total = len(start_bytes)


for i, search_str in enumerate(start_bytes):
    start_size = len(search_str.split(" "))
    print(f"Progress: {i + 1}/{total}")
    for ea in get_binary_results(search_str):
        size = idc.next_head(ea) - ea
        data = ida_bytes.get_bytes(ea, size)
        str_addr = BASE + int.from_bytes(data[start_size:], "little")
        if is_in_rdata(str_addr):
            if idc.get_strlit_contents(str_addr) is not None:
                count += 1
                create_xref(ea, str_addr)

print(f"Added xrefs to {count} strings!")
