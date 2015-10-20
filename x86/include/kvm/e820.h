#ifndef KVM_E820_H
#define KVM_E820_H

#include <kvm/bios.h>
#include <asm/e820.h>

#define SMAP    0x534d4150      /* ASCII "SMAP" */

#define E820MAX 128             /* number of entries in E820MAP */
#define E820_X_MAX E820MAX

#define E820_RAM        1
#define E820_RESERVED   2

struct biosregs;

extern bioscall void e820_query_map(struct biosregs *regs);

#endif /* KVM_E820_H */
