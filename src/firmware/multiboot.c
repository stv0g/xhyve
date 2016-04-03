/*-
 * Copyright (c) 2016, Steffen Vogel
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY ???, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Multiboot Specivication 1 compliant firmware loader.
 *
 * See: https://www.gnu.org/software/grub/manual/multiboot/multiboot.pdf
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <xhyve/vmm/vmm_api.h>
#include <xhyve/firmware/multiboot.h>

static struct {
	char *kernel;
	char *cmdline;
	char *modules[16];
} config;

static
int
multiboot_parse_image(const char *image, struct multiboot_header *hdr) {
	FILE *f;
	uint32_t *head;
	size_t bytes;
	int i, ret = -1;
	
	f = fopen(image, "r");
	if (!f) {
		fprintf(stderr, "Failed to load kernel image: %s", strerror(errno));
		return -1;
	}
	
	head = malloc(MULTIBOOT_SEARCH);
	if (!head)
		return -2;
	
	bytes = fread(head, 1, MULTIBOOT_SEARCH, f);
	
	/* Search Multiboot magic */
	for (i = 0; i < bytes / sizeof(*head); i++) {
		if (head[i] == MULTIBOOT_HEADER_MAGIC) {
			memcpy(hdr, &head[i]);

			/* Verify checksum */
			ret = (hdr->magic + hdr->flags + hdr->checksum == 0) ? 0 : -3;

			break;
		}
	}
	
	free(head);
	fclose(f);
	
	return ret;
}

int
multiboot_init(char *opts[]) {
	config.kernel = opts[0];
	config.cmdline = opts[1];
	config.modules = &opts[2];
	
	return 0;
}

uint64_t
multiboot(void)
{
	int ret, i;
	char *module;
	struct multiboot_header hdr;

	/* Check integrity and load header of multiboot image */
	ret = multiboot_parse_image(config.kernel, &hdr);
	if (ret)
		abort();
	
	/* Load OS image (kernel) */
	ret = multiboot_load_kernel(config.kernel, hdr.load_addr, hdr.load_end_addr);
	if (ret)
		abort();

	/* Load modules (initrd..) */
	for (i = 0; i < 16 && module = config.modules[i]; i++) {
		FILE *f = fopen(module, "r");
		if (f) {
			multiboot_load_module(module);
		}
		else {
			fprintf(stderr, "Failed to open module: %s\n", module);
		}
	}
	
	/* Prepare machine state. See: Section 3.2 of Multiboot spec 0.6 */
	xh_vcpu_reset(0);

	xh_vm_set_desc(0, VM_REG_GUEST_GDTR, BASE_GDT, 0x1f, 0);
	xh_vm_set_desc(0, VM_REG_GUEST_CS, 0, 0xffffffff, 0xc09b);
	xh_vm_set_desc(0, VM_REG_GUEST_DS, 0, 0xffffffff, 0xc093);
	xh_vm_set_desc(0, VM_REG_GUEST_ES, 0, 0xffffffff, 0xc093);
	xh_vm_set_desc(0, VM_REG_GUEST_SS, 0, 0xffffffff, 0xc093);

	xh_vm_set_register(0, VM_REG_GUEST_CS, 0x10);
	xh_vm_set_register(0, VM_REG_GUEST_DS, 0x18);
	xh_vm_set_register(0, VM_REG_GUEST_ES, 0x18);
	xh_vm_set_register(0, VM_REG_GUEST_SS, 0x18);

	xh_vm_set_register(0, VM_REG_GUEST_CR0, CR0_PE);
	xh_vm_set_register(0, VM_REG_GUEST_RFLAGS, 0);

	xh_vm_set_register(0, VM_REG_GUEST_RBP, 0);
	xh_vm_set_register(0, VM_REG_GUEST_RDI, 0);
	xh_vm_set_register(0, VM_REG_GUEST_RBX, /* MB info struct */);
	xh_vm_set_register(0, VM_REG_GUEST_RSI, );
	xh_vm_set_register(0, VM_REG_GUEST_RIP, );
	xh_vm_set_register(0, VM_REG_GUEST_RAX, 0x2BADB002);

	return kernel.base;
}
