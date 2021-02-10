#!/bin/sh

# Run as ./run_headless PATH_TO_BINARY

ghidra="XXX" # base directory of ghidra
script="YYY" # directory where ghidra_script.py is located

$ghidra/support/analyzeHeadless /tmp ctf_hacking -import $1 -postScript $script/ghidra_script.py

rm /tmp/ctf_hacking.gpr
rm -r /tmp/ctf_hacking.rep
