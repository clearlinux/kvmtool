#ifndef _ASM_X86_PROCESSOR_FLAGS_H
#define _ASM_X86_PROCESSOR_FLAGS_H
/* Various flags defined: can be included from assembler. */

/*
 * EFLAGS bits
 */
#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */

/*
 * Basic CPU control in CR0
 */
#define X86_CR0_PE_BIT		0 /* Protection Enable */
#define X86_CR0_PE		_BITUL(X86_CR0_PE_BIT)
#define X86_CR0_PG_BIT		31 /* Paging */
#define X86_CR0_PG		_BITUL(X86_CR0_PG_BIT)

/*
 * Intel CPU features in CR4
 */
#define X86_CR4_PAE_BIT		5 /* enable physical address extensions */
#define X86_CR4_PAE		_BITUL(X86_CR4_PAE_BIT)

#endif
