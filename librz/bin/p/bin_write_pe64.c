/* radare - LGPL - Copyright 2009-2017 pancake */

#define RZ_BIN_PE64 1
#include "bin_write_pe.c"

RzBinWrite rz_bin_write_pe64 = {
	.scn_perms = &scn_perms
};
