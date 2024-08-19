# IDA string xref and binary migration scripts

NOTE: This repo is in a very early stage. The code is not usable without a decent amount of fiddling, so use with care.

The purpose of this repo is two-fold:
- Provide a script which helps to find and add more string xrefs which IDA doesn't seem to find well (may only really work on the windows build of NMS.)
- Provide a way to migrate names from one binary version to another by comparing string xrefs between the two versions (as well as other methods in the future hopefully!)

## Usage

In the following we define _source_ as the original binary (ie. the one with all/most functions named), and _target_ as the binary which you wish to map the names to.

1. Run `more_string_xrefs.py` on both _source_ and _target_ exe's in IDA.
1. Ensure that `save_string_xrefs.py` has `named = True` (line 25) and run this script on the _source_ exe.
1. Modify that same file and have `named = False`, and run the script on the _target_ exe.
1. Run `load_string_refs.py` in either exe.
1. Once that has completed, run `rename_funcs.py` in the _target_ exe.
