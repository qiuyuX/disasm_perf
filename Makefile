disasm_perf: disasm_perf.c
	gcc disasm_perf.c -lxed -lcapstone -lZydis -lgmp -O3 -Wall -o disasm_perf
