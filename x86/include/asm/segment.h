#ifndef _ASM_X86_SEGMENT_H
#define _ASM_X86_SEGMENT_H

#include <linux/const.h>

/* Constructor for a conventional segment GDT (or LDT) entry */
/* This is a macro so it can be used in initializers */
#define GDT_ENTRY(flags, base, limit)                   \
	((((base)  & _AC(0xff000000,ULL)) << (56-24)) | \
	(((flags) & _AC(0x0000f0ff,ULL)) << 40) |      \
	(((limit) & _AC(0x000f0000,ULL)) << (48-16)) | \
	(((base)  & _AC(0x00ffffff,ULL)) << 16) |      \
	 (((limit) & _AC(0x0000ffff,ULL))))

#endif /* _ASM_X86_SEGMENT_H */
