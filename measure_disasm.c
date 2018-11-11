/* By Qiuyu Xiao <qiuyu.xiao.qyx@gmail.com>, 2018 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <inttypes.h>
#include <getopt.h>
#include <gmp.h>
#include <capstone/capstone.h>
#include "xed/xed-interface.h"

mpz_t sum; // Total CPU cycles on disassembling
mpz_t count; // The number of instructions being disassembled
int is_xed = 0; // True if use xed
int is_capstone = 0; // True if use capstone
int detailed_mode = 0; // Flag set by --detail, used by capstone
struct option options[] =
{
    {"xed", no_argument, NULL, 'x'},
    {"capstone", no_argument, NULL, 'c'},
    {"detail", no_argument, NULL, 'd'},
    {0, 0, 0, 0}
};

// Convert ascii repretation of hex digit to decimal value
uint8_t ascii_to_uint(char ascii)
{
    uint8_t ret;

    if (ascii >= '0' && ascii <= '9') {
        ret = ascii - '0';
    } else if (ascii >= 'a' && ascii <= 'f') {
        ret = ascii - 'a' + 10;
    } else {
        perror("Invalid instruction ascii encoding.\n");
        exit(1);
    }

    return ret;
}

// Convert two bytes of ascii string to hex byte, e.g., 'af' -> 0xaf.
uint8_t asciis_to_hex_byte(char ascii_0, char ascii_1)
{
    uint8_t ret;

    ret = ascii_to_uint(ascii_0);
    ret = ret << 4;
    ret += ascii_to_uint(ascii_1);

    return ret;
}

// Convert ascii encoded array to hex array.
void asciis_to_hex_arr(char* ascii, uint8_t* hex, int len)
{
    if ((len % 2) != 0) {
        perror("The inst ascii array should be even number of bytes.\n");
        exit(1);
    }

    for (int i = 0; i < len; i += 2)
        hex[i / 2] = asciis_to_hex_byte(ascii[i], ascii[i + 1]);
}

// Use Intel XED to decode instruction
void do_xed()
{
    xed_state_t state;
    xed_decoded_inst_t xedd;
    char inst_ascii[32]; // ASCII representation of the instruction
    uint8_t inst_hex[15]; // HEX value of the instruction
    int len; // ASCII string length
    uint64_t t1, t2;

    // Initialize xed
    xed_tables_init();
    xed_state_zero(&state);
    state.mmode = XED_MACHINE_MODE_LONG_64;
    state.stack_addr_width = XED_ADDRESS_WIDTH_64b;

    while (1) {
        char* ret;
        xed_error_enum_t xed_error;

        ret = fgets(inst_ascii, 32, stdin);
        if (!ret) {
            if (ferror(stdin)) {
                printf("Read error from stdin.\n");
                exit(1);
            } else {// EOF
                break;
            }
        }

        len = strlen(inst_ascii);
        // Array should end with \n\0
        if (inst_ascii[len - 1] != '\n') {
            perror("Invalid ascii array encoding.\n");
            exit(1);
        }

        asciis_to_hex_arr(inst_ascii, inst_hex, len - 1);

        // Measure disassembling time
        asm volatile(
                     "rdtsc\n\t"
                     "shl $32, %%rdx\n\t"
                     "or %%rdx, %0"
                     : "=a" (t1)
                     :
                     : "rdx");

        // xed_decoded_inst_t has to be re-initialized, otherwise we get wrong
        // results
        xed_decoded_inst_zero_set_mode(&xedd, &state);
        xed_error = xed_decode(&xedd,
                            XED_REINTERPRET_CAST(const xed_uint8_t*, inst_hex),
                            (len - 1) / 2);

        asm volatile(
                     "rdtsc\n\t"
                     "shl $32, %%rdx\n\t"
                     "or %%rdx, %0"
                     : "=a" (t2)
                     :
                     : "rdx");

        // Add up disassembling time
        mpz_add_ui(sum, sum, t2 - t1);
        mpz_add_ui(count, count, 1);

        if (xed_error != XED_ERROR_NONE) {
            perror("XED error.\n");
            exit(1);
        }
    }
}

void do_capstone()
{
	csh handle;
	cs_insn* insn;
    char inst_ascii[32]; // ASCII representation of the instruction
    uint8_t inst_hex[15]; // HEX value of the instruction
    int len; // ASCII string length
    size_t size;
    uint8_t* code;
    uint64_t address = 0;
    uint64_t t1, t2;

    // Initialize capstone
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
		perror("ERROR: Failed to initialize capstone!\n");
		exit(1);
	}

    if (detailed_mode) { // Get detailed decoding results
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    } else {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    }

    insn = cs_malloc(handle);

    while (1) {
        char* ret;
        bool success;

        ret = fgets(inst_ascii, 32, stdin);
        if (!ret) {
            if (ferror(stdin)) {
                perror("Read error from stdin.\n");
                exit(1);
            } else { // EOF
                break;
            }
        }

        len = strlen(inst_ascii);
        // Array should end with \n\0
        if (inst_ascii[len - 1] != '\n') {
            perror("Invalid ascii array encoding.\n");
            exit(1);
        }
        asciis_to_hex_arr(inst_ascii, inst_hex, len - 1);
        code = inst_hex;
        size = (len - 1) / 2;

        // Measure disassembling time
        asm volatile(
                     "rdtsc\n\t"
                     "shl $32, %%rdx\n\t"
                     "or %%rdx, %0"
                     : "=a" (t1)
                     :
                     : "rdx");

        success = cs_disasm_iter(handle, (const uint8_t**)&code,
                                 &size, &address, insn);

        asm volatile(
                     "rdtsc\n\t"
                     "shl $32, %%rdx\n\t"
                     "or %%rdx, %0"
                     : "=a" (t2)
                     :
                     : "rdx");

        // Add up disassembling time
        mpz_add_ui(sum, sum, t2 - t1);
        mpz_add_ui(count, count, 1);

        if (!success) {
            perror("Capstone disasm error.\n");
            exit(1);
        }
    }

    cs_free(insn, 1);
	cs_close(&handle);
}

int main(int argc, char** argv)
{
    int o;
    int option_index;
    cpu_set_t mask;

    // Set process to a fixed CPU so that migration dosen't mess up rdtsc
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask)) {
        perror("Failed to set CPU affinity.\n");
        exit(1);
    }

    // Initialize counters
    mpz_init(sum);
    mpz_init(count);

    while ((o = getopt_long(argc, argv, "xcd", options, &option_index)) != -1) {
        switch (o) {
            case 'x':
                is_xed = 1;
                break;
            case 'c':
                is_capstone = 1;
                break;
            case 'd':
                detailed_mode = 1;
                break;
            default:
                perror("Not a valid option.\n");
                exit(1);
        }
    }

    if ((is_xed && is_capstone) || (!is_xed && !is_capstone)) {
        perror("Please choose either capstone or xed decoding.\n");
        exit(1);
    } else if (is_xed) {
        do_xed();
    } else if (is_capstone) {
        do_capstone();
    }

    if (mpz_cmp_ui(count, 0) == 0) {
        perror("No decoding execution was executed.\n");
        exit(1);
    }

    mpz_cdiv_q(sum, sum, count);
    printf("Average decoding time (cycles): ");
    mpz_out_str(stdout, 10, sum);
    printf("\n");

    mpz_clear(sum);
    mpz_clear(count);

    return 0;
}
