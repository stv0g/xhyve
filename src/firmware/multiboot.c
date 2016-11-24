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
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/elf32.h>

#include <xhyve/vmm/vmm_api.h>
#include <xhyve/firmware/multiboot.h>

#ifndef ALIGNUP
  #define ALIGNUP(x, a) (((x - 1) & ~(a - 1)) + a)
#endif

#define MAX_MODULES 16

int nmodules; /* number of modules */

static struct mod {
	char *path;
	char *cmdline;

	char *base;
	size_t size;
	off_t offset;
} memory, kernel, bss, modules[MAX_MODULES];

static int
multiboot_parse_image(const char *image, struct multiboot_header *hdr) {
	FILE *f;
	uint32_t *head;
	size_t bytes;
	int ret = -1;
	unsigned i;
	
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
			memcpy(hdr, &head[i], sizeof(*hdr));

			/* Verify checksum */
			ret = (hdr->magic + hdr->flags + hdr->checksum == 0) ? 0 : -3;

			break;
		}
	}
	
	free(head);
	fclose(f);
	
	return ret;
}

#if 0
static int
multiboot_parse_elf(struct mod *kernel, struct mod *bss, uint32_t *entrypoint) {
	FILE *f;
	
	struct elfhdr *ehdr;
	struct elf_phdr *phdr;

	int i;
	ssize_t sz, pos, bytes;
	loff_t offset;
	
	f = fopen(kernel->path, "r");
	if (!f)
		return -1;
	
	buf = malloc(sizeof(*ehdr));
	if (buf == NULL)
		return -1;
		
	if (fread(ehdr, sizeof(*ehdr), 1, f) != sizeof(*ehdr))
		return -1;

	/* Check if this is an ELF file */
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
		return -1;

	if (ehdr->e_phoff == 0)
		return -1;

	if (!elf_check_arch(ehdr))
		return -1;

	for (i=0; i<ehdr->e_phnum; i++) {
		phdr = ehdr->e_phoff + i * ehdr->e_phentsize;

		if (phdr->p_type == PT_LOAD) {
			kernel->offset = phdr->p_offset;
			kernel->base   =
			kernel->size   = phdr->p_filesz;

			fclose(f);
			return 0;
		}
	}

	fclose(f);

	return -1; /* Missing PT_LOAD segment */
}
#endif

static int
multiboot_load(struct mod *lowmem, struct mod *module) {
	FILE *f;
	size_t n;
	
	if (module->base + module->size > lowmem->size)
		return -1;
	
	f = fopen(module->path, "r");
	if (!f)
		return -1;
	
	n = fread(lowmem->base + module->base, module->size, 1, f);
	
	fclose(f);

	return n == 1 ? 0 : -1;
}

int
multiboot_init(char *opts[]) {
	
	kernel.path = opts[0];
	kernel.cmdline = opts[1];
	
	/* TODO: parse cmdline: "kernel=kernel_cmdline,module1=module1_cmdline,..." */
	for (nmodules = 0; nmodules < MAX_MODULES && opts[2 + nmodules]; nmodules++)
		modules[nmodules].path = opts[2 + nmodules];
	
	return 0;
}

uint64_t
multiboot(void)
{
	int ret, i;
	char *module;
	struct multiboot_header mbhdr;
	struct multiboot_info  *mbinfo;
	struct stat st;
	
	uint32_t entrypoint;
	uintptr_t addr;

	/* Map low memory for VM */
	memory.base = (uintptr_t) xh_vm_map_gpa(0, xh_vm_get_lowmem_size());
	memory.size = xh_vm_get_lowmem_size();

	/* Check integrity and load header of multiboot image */
	ret = multiboot_parse_image(config.kernel, &mbhdr);
	if (ret)
		abort();
	
	/* Get address to load kernel */
	if (mbhdr.flags & MULTIBOOT_AOUT_KLUDGE) {
		kernel.base = mbhdr.load_addr;
		kernel.size = mbhdr.load_end_addr - kernel.base;
		
		bss.base = kernel.base + kernel.size;
		bss.size = mbhdr.bss_end_addr - bss.base;
			
		entrypoint = mbhdr.entry_addr;
	}
	/* use ELF header instead */
	else {
		ret = multiboot_parse_elf(&kernel, &bss, &entrypoint);
		if (ret)
			abort();
	}
	
	/* Load OS image (kernel) */
	ret = multiboot_load_kernel(config.kernel, kernel.addr, );
	if (ret)
		abort();
	
	/* Initialize bss section */
	memset(memory.base + bss.base, 0. bss.size);
	
	mbinfo->flags = 0;
	
	mbinfo = memory.base + BASE_MBINFO;

	/* Available memory range */
	mbinfo->flags |= MULTIBOOT_INFO_MEMORY;
	mbinfo->mem_lower = memory.base;
	mbinfo->mem_upper = memory.base + memory.size;

	/* Kernel cmdline */
	mbinfo->flags |= MULTIBOOT_INFO_CMDLINE;
	mbinfo->cmdline = BASE_CMDLINE;
	strcpy(memory.base + BASE_CMDLINE, kernel.cmdline);

	/* Multiboot modules */
	mbinfo->flags |= MULTIBOOT_INFO_MODS;
	mbinfo->mods_count = 0;
	mbinfo->mods_addr = BASE_MBMODS;

	/* Load modules (initrd..) after bss section */
	addr = bss.base + bss.size;
	for (i = 0; i < nmodules; i++) {
		struct multiboot_mod_list *mbmod = memory.base + BASE_MBMODS + i * sizeof(*mbmods);
		struct mod *module = &modules[i];
		
		ret = stat(module->path, &st);
		if (ret)
			abort();
		
		module->offset = 0;
		module->size = st.st_size;
		module->base = mbinfo->flags & MULTIBOOT_PAGE_ALIGN
			? ALIGNUP(addr, MULTIBOOT_MOD_ALIGN)
			: addr;
		
		ret = multiboot_load(module);
		if (ret)
			abort();
		
		mbmod->mod_start = (multiboot_uint32_t) module->base;
		mbmod->mod_end   = (multiboot_uint32_t) module->base + module->size;
		mbmod->cmdline   = module->cmdline;
		
		mbinfo->mods_count++;
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
	xh_vm_set_register(0, VM_REG_GUEST_RBX, BASE_MBINFO);
	xh_vm_set_register(0, VM_REG_GUEST_RSI, 0);
	xh_vm_set_register(0, VM_REG_GUEST_RIP, entrypoint);
	xh_vm_set_register(0, VM_REG_GUEST_RAX, MULTIBOOT_BOOTLOADER_MAGIG);

	return kernel.base;
}
