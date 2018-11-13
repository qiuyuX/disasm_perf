measure_disasm: measure_disasm.c
	gcc measure_disasm.c -lxed -lcapstone -lZydis -lgmp -O3 -Wall -o measure_disasm
