#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <platform.h>
#include <capstone.h>

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	char *comment;
};

static csh handle;

static void print_string_hex(char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

#define RISCV_CODE "\x97\x04\x00\x00\x83\xa4\x44\x03\x97\x09\x00\x00\x83\xa9\x09\x03\x17\x04\x00\x00\x03\x24\x04\x02\x33\x09\x39\x01\x13\x04\x44\x00\x33\x0a\x89\x00\x23\x20\x44\x01\xe3\x54\x94\xfe\x6f\xf0\x1f\xff\x00\x00\x00\x90\x00\x70\x17\x90\x20\x00\x00\x00"

static int read_binary_file(char* filename, char**buffer, int* len)
{
	FILE *file;
	char *buf;

	//Open file
	file = fopen(filename, "rb");
	if (!file)
	{
		fprintf(stderr, "Unable to open file %s\n", filename);
		return 1;
	}

	fseek(file, 0, SEEK_END);
	*len = ftell(file);
	fseek(file, 0, SEEK_SET);

	buf = malloc(*len+1);
	if (!buf)
	{
		fprintf(stderr, "Allocation error!\n");
		*len = 0;
		fclose(file);
		return 1;
	}

	//Read file contents into buffer
	fread(buf, *len, 1, file);
	fclose(file);
	*buffer = buf;

	return 0;
}

static void print_insn_detail(cs_insn *ins)
{
	int i;
	cs_riscv *riscv;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	riscv = &(ins->detail->riscv);
	if (riscv->op_count)
		printf("\top_count: %u\n", riscv->op_count);

	for (i = 0; i < riscv->op_count; i++) {
		cs_riscv_op *op = &(riscv->operands[i]);
		switch((int)op->type) {
			default:
				assert(0 && "Unknown instruction type");
				break;
			case RISCV_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case RISCV_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
		}
	}
	printf("\n");

	// print the groups this instruction belong to
	if (ins->detail->groups_count > 0) {
		printf("\tThis instruction belongs to groups: ");
		for (i = 0; i < ins->detail->groups_count; i++) {
			printf("%s ", cs_group_name(handle, ins->detail->groups[i]));
		}
		printf("\n");
	}
}

#define MAX_FILENAME_LEN 256

static int test()
{
	char *blocks_buffer;
	int blocks_len;
	char *data_dir = getenv("CAPSTONE_TEST_DATA_DIR");
	char data_file[MAX_FILENAME_LEN];
	int rc = 0;

	if (data_dir) {
		snprintf(data_file, MAX_FILENAME_LEN, "%s/%s", data_dir, "riscv_blocks.img");
	} else {
		snprintf(data_file, MAX_FILENAME_LEN, "%s", "./test_data/riscv_blocks.img");
	}

	rc = read_binary_file(data_file, &blocks_buffer, &blocks_len);
	if (rc)
		return rc;
	struct platform platforms[] = {
		{
			CS_ARCH_RISCV,
			(cs_mode)(CS_MODE_32),
			(unsigned char *)RISCV_CODE,
			sizeof(RISCV_CODE) - 1,
			"RV32IM"
		},
		{
			CS_ARCH_RISCV,
			(cs_mode)(CS_MODE_32),
			(unsigned char *)blocks_buffer,
			blocks_len,
			"RV32IM"
		},
	};
	uint64_t address = 0x42000000; /* TODO: Hardcoded offset */
	cs_insn *insn;
	int i;
	size_t count;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			continue;
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

		count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
		if (count) {
			size_t j;

			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
				print_insn_detail(&insn[j]);
			}
			printf("0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
			rc = 1;
		}

		// TODO: Check that the last address is as expected

		printf("\n");

		cs_close(&handle);
	}

	free(blocks_buffer);

	return rc;
}


int main(void)
{
	return test();
}
