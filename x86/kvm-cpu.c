#include "kvm/kvm-cpu.h"

#include "kvm/symbol.h"
#include "kvm/util.h"
#include "kvm/kvm.h"

#include <asm/msr-index.h>
#include <asm/processor-flags.h>
#include <asm/ldt.h>
#include <asm/apicdef.h>
#include <asm/segment.h>
#include <linux/err.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

static int debug_fd;

void kvm_cpu__set_debug_fd(int fd)
{
	debug_fd = fd;
}

int kvm_cpu__get_debug_fd(void)
{
	return debug_fd;
}

static inline bool is_in_protected_mode(struct kvm_cpu *vcpu)
{
	return vcpu->sregs.cr0 & 0x01;
}

static inline u64 ip_to_flat(struct kvm_cpu *vcpu, u64 ip)
{
	u64 cs;

	/*
	 * NOTE! We should take code segment base address into account here.
	 * Luckily it's usually zero because Linux uses flat memory model.
	 */
	if (is_in_protected_mode(vcpu))
		return ip;

	cs = vcpu->sregs.cs.selector;

	return ip + (cs << 4);
}

static inline u32 selector_to_base(u16 selector)
{
	/*
	 * KVM on Intel requires 'base' to be 'selector * 16' in real mode.
	 */
	return (u32)selector << 4;
}

static struct kvm_cpu *kvm_cpu__new(struct kvm *kvm)
{
	struct kvm_cpu *vcpu;

	vcpu = calloc(1, sizeof(*vcpu));
	if (!vcpu)
		return NULL;

	vcpu->kvm = kvm;

	return vcpu;
}

void kvm_cpu__delete(struct kvm_cpu *vcpu)
{
	if (vcpu->msrs)
		free(vcpu->msrs);

	free(vcpu);
}

static int kvm_cpu__set_lint(struct kvm_cpu *vcpu)
{
	struct local_apic lapic;

	if (ioctl(vcpu->vcpu_fd, KVM_GET_LAPIC, &lapic))
		return -1;

	lapic.lvt_lint0.delivery_mode = APIC_MODE_EXTINT;
	lapic.lvt_lint1.delivery_mode = APIC_MODE_NMI;

	return ioctl(vcpu->vcpu_fd, KVM_SET_LAPIC, &lapic);
}

struct kvm_cpu *kvm_cpu__arch_init(struct kvm *kvm, unsigned long cpu_id)
{
	struct kvm_cpu *vcpu;
	int mmap_size;
	int coalesced_offset;

	vcpu = kvm_cpu__new(kvm);
	if (!vcpu)
		return NULL;

	vcpu->cpu_id = cpu_id;

	vcpu->vcpu_fd = ioctl(vcpu->kvm->vm_fd, KVM_CREATE_VCPU, cpu_id);
	if (vcpu->vcpu_fd < 0)
		die_perror("KVM_CREATE_VCPU ioctl");

	mmap_size = ioctl(vcpu->kvm->sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (mmap_size < 0)
		die_perror("KVM_GET_VCPU_MMAP_SIZE ioctl");

	vcpu->kvm_run = mmap(NULL, mmap_size, PROT_RW, MAP_SHARED, vcpu->vcpu_fd, 0);
	if (vcpu->kvm_run == MAP_FAILED)
		die("unable to mmap vcpu fd");

	coalesced_offset = ioctl(kvm->sys_fd, KVM_CHECK_EXTENSION, KVM_CAP_COALESCED_MMIO);
	if (coalesced_offset)
		vcpu->ring = (void *)vcpu->kvm_run + (coalesced_offset * PAGE_SIZE);

	if (kvm_cpu__set_lint(vcpu))
		die_perror("KVM_SET_LAPIC failed");

	vcpu->is_running = true;

	return vcpu;
}

static struct kvm_msrs *kvm_msrs__new(size_t nmsrs)
{
	struct kvm_msrs *vcpu = calloc(1, sizeof(*vcpu) + (sizeof(struct kvm_msr_entry) * nmsrs));

	if (!vcpu)
		die("out of memory");

	return vcpu;
}

#define KVM_MSR_ENTRY(_index, _data)	\
	(struct kvm_msr_entry) { .index = _index, .data = _data }

static void kvm_cpu__setup_msrs(struct kvm_cpu *vcpu)
{
	unsigned long ndx = 0;

	vcpu->msrs = kvm_msrs__new(100);

	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_IA32_SYSENTER_CS,	0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_IA32_SYSENTER_ESP,	0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_IA32_SYSENTER_EIP,	0x0);
#ifdef CONFIG_X86_64
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_STAR,			0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_CSTAR,			0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_KERNEL_GS_BASE,		0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_SYSCALL_MASK,		0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_LSTAR,			0x0);
#endif
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_IA32_TSC,		0x0);
	vcpu->msrs->entries[ndx++] = KVM_MSR_ENTRY(MSR_IA32_MISC_ENABLE,
						MSR_IA32_MISC_ENABLE_FAST_STRING);

	vcpu->msrs->nmsrs = ndx;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_MSRS, vcpu->msrs) < 0)
		die_perror("KVM_SET_MSRS failed");
}

static void kvm_cpu__setup_fpu(struct kvm_cpu *vcpu)
{
	vcpu->fpu = (struct kvm_fpu) {
		.fcw	= 0x37f,
		.mxcsr	= 0x1f80,
	};

	if (ioctl(vcpu->vcpu_fd, KVM_SET_FPU, &vcpu->fpu) < 0)
		die_perror("KVM_SET_FPU failed");
}

static void kvm_cpu__setup_regs(struct kvm_cpu *vcpu)
{
	vcpu->regs = (struct kvm_regs) {
		/* We start the guest in 16-bit real mode  */
		.rflags	= 0x0000000000000002ULL,

		.rip	= vcpu->kvm->arch.boot_ip,
		.rsp	= vcpu->kvm->arch.boot_sp,
		.rbp	= vcpu->kvm->arch.boot_sp,
		.rsi    = vcpu->kvm->arch.boot_si,
	};

	if (!vcpu->kvm->arch.boot_protected && vcpu->regs.rip > USHRT_MAX)
		die("ip 0x%llx is too high for real mode", (u64)vcpu->regs.rip);

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &vcpu->regs) < 0)
		die_perror("KVM_SET_REGS failed");
}

static void prot32_sregs(struct kvm_cpu *vcpu)
{
}

#define BOOT_GDT	0x500
#define BOOT_IDT	0x520

#define BOOT_GDT_NULL	0
#define BOOT_GDT_CODE	1
#define BOOT_GDT_DATA	2
#define BOOT_GDT_TSS	3
#define BOOT_GDT_MAX	4

/* Puts PML4 right after zero page but aligned to 4k */
#define BOOT_PML4	0x9000
#define BOOT_PDPTE	0xA000

/*
 * We need to build a kvm_segment struct to represent each
 * of the GDT entries we've created. These macros help keep
 * the entries consistent by automatically building the
 * struct based on the gdt fields
 */
#define GDT_GET_BASE(x) \
        (( (x) & 0xFF00000000000000) >> 32) | \
        (( (x) & 0x000000FF00000000) >> 16) | \
        (( (x) & 0x00000000FFFF0000) >> 16)

#define GDT_GET_LIMIT(x) (__u32)( \
        (( (x) & 0x000F000000000000) >> 32) | \
        (( (x) & 0x000000000000FFFF)))

#define GDT_GET_G(x)   (__u8)(( (x) & 0x0080000000000000) >> 55)
#define GDT_GET_DB(x)  (__u8)(( (x) & 0x0040000000000000) >> 54)
#define GDT_GET_L(x)   (__u8)(( (x) & 0x0020000000000000) >> 53)
#define GDT_GET_AVL(x) (__u8)(( (x) & 0x0010000000000000) >> 52)
#define GDT_GET_P(x)   (__u8)(( (x) & 0x0000800000000000) >> 47)
#define GDT_GET_DPL(x) (__u8)(( (x) & 0x0000600000000000) >> 45)
#define GDT_GET_S(x)   (__u8)(( (x) & 0x0000100000000000) >> 44)
#define GDT_GET_TYPE(x)(__u8)(( (x) & 0x00000F0000000000) >> 40)

#define GDT_TO_KVM_SEGMENT(seg, gdt_table, sel) \
do { \
	__u64 gdt_ent = gdt_table[sel]; \
	seg.base = GDT_GET_BASE(gdt_ent); \
	seg.limit = GDT_GET_LIMIT(gdt_ent); \
	seg.selector = sel * 8; \
	seg.type = GDT_GET_TYPE(gdt_ent); \
	seg.present = GDT_GET_P(gdt_ent); \
	seg.dpl = GDT_GET_DPL(gdt_ent); \
	seg.db = GDT_GET_DB(gdt_ent); \
	seg.s = GDT_GET_S(gdt_ent); \
	seg.l = GDT_GET_L(gdt_ent); \
	seg.g = GDT_GET_G(gdt_ent); \
	seg.avl = GDT_GET_AVL(gdt_ent); \
} while (0);

static void prot64_sregs(struct kvm_cpu *vcpu)
{
	void *p;

	__u64 idt = 0;
	__u64 gdt[BOOT_GDT_MAX] = {	/* flags, base, limit */
		[BOOT_GDT_NULL] = GDT_ENTRY(0, 0, 0),
		[BOOT_GDT_CODE] = GDT_ENTRY(0xA09B, 0, 0xFFFFF),
		[BOOT_GDT_DATA] = GDT_ENTRY(0xC093, 0, 0xFFFFF),
		[BOOT_GDT_TSS ] = GDT_ENTRY(0x808B, 0, 0xFFFFF),
	};

	struct kvm_segment data_seg, code_seg, tss_seg;

	GDT_TO_KVM_SEGMENT(code_seg, gdt, BOOT_GDT_CODE);
	GDT_TO_KVM_SEGMENT(data_seg, gdt, BOOT_GDT_DATA);
	GDT_TO_KVM_SEGMENT(tss_seg,  gdt, BOOT_GDT_TSS);

/* Segments */
	p = guest_flat_to_host(vcpu->kvm, BOOT_GDT);
	memcpy(p, gdt, sizeof(gdt));
	vcpu->sregs.gdt.base = BOOT_GDT;
	vcpu->sregs.gdt.limit = sizeof(gdt)-1;

	p = guest_flat_to_host(vcpu->kvm, BOOT_IDT);
	memcpy(p, &idt, sizeof(idt));
	vcpu->sregs.idt.base = BOOT_IDT;
	vcpu->sregs.idt.limit = sizeof(idt)-1;

	vcpu->sregs.cs = code_seg;
	vcpu->sregs.ds = data_seg;
	vcpu->sregs.es = data_seg;
	vcpu->sregs.fs = data_seg;
	vcpu->sregs.gs = data_seg;
	vcpu->sregs.ss = data_seg;
	vcpu->sregs.tr = tss_seg;

/* Page Tables */
	p = guest_flat_to_host(vcpu->kvm, BOOT_PML4);
	memset(p, 0, 4096);
	*(__u64 *)p = (__u64)(BOOT_PDPTE | 3);

	p = guest_flat_to_host(vcpu->kvm, BOOT_PDPTE);
	memset(p, 0, 4096);
	*(__u64 *)p = 0x83;

	vcpu->sregs.cr3 = BOOT_PML4;
	vcpu->sregs.cr4 |= X86_CR4_PAE;
	vcpu->sregs.cr0 |= X86_CR0_PG;

/* 64-bit protected mode */
	vcpu->sregs.cr0 |= X86_CR0_PE;
	vcpu->sregs.efer |= EFER_LME;
}

static void kvm_cpu__setup_sregs(struct kvm_cpu *vcpu)
{
	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &vcpu->sregs) < 0)
		die_perror("KVM_GET_SREGS failed");

	vcpu->sregs.cs.selector	= vcpu->kvm->arch.boot_selector;
	vcpu->sregs.cs.base	= selector_to_base(vcpu->kvm->arch.boot_selector);
	vcpu->sregs.ss.selector	= vcpu->kvm->arch.boot_selector;
	vcpu->sregs.ss.base	= selector_to_base(vcpu->kvm->arch.boot_selector);
	vcpu->sregs.ds.selector	= vcpu->kvm->arch.boot_selector;
	vcpu->sregs.ds.base	= selector_to_base(vcpu->kvm->arch.boot_selector);
	vcpu->sregs.es.selector	= vcpu->kvm->arch.boot_selector;
	vcpu->sregs.es.base	= selector_to_base(vcpu->kvm->arch.boot_selector);
	vcpu->sregs.fs.selector	= vcpu->kvm->arch.boot_selector;
	vcpu->sregs.fs.base	= selector_to_base(vcpu->kvm->arch.boot_selector);
	vcpu->sregs.gs.selector	= vcpu->kvm->arch.boot_selector;
	vcpu->sregs.gs.base	= selector_to_base(vcpu->kvm->arch.boot_selector);

	if (vcpu->kvm->arch.boot_protected && vcpu->cpu_id == 0) {
		if (vcpu->kvm->arch.boot_64)
			prot64_sregs(vcpu);
		else
			prot32_sregs(vcpu);
	}

	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs) < 0)
		die_perror("KVM_SET_SREGS failed");
}

/**
 * kvm_cpu__reset_vcpu - reset virtual CPU to a known state
 */
void kvm_cpu__reset_vcpu(struct kvm_cpu *vcpu)
{
	kvm_cpu__setup_cpuid(vcpu);
	kvm_cpu__setup_sregs(vcpu);
	kvm_cpu__setup_regs(vcpu);
	kvm_cpu__setup_fpu(vcpu);
	kvm_cpu__setup_msrs(vcpu);
}

bool kvm_cpu__handle_exit(struct kvm_cpu *vcpu)
{
	return false;
}

static void print_dtable(const char *name, struct kvm_dtable *dtable)
{
	dprintf(debug_fd, " %s                 %016llx  %08hx\n",
		name, (u64) dtable->base, (u16) dtable->limit);
}

static void print_segment(const char *name, struct kvm_segment *seg)
{
	dprintf(debug_fd, " %s       %04hx      %016llx  %08x  %02hhx    %x %x   %x  %x %x %x %x\n",
		name, (u16) seg->selector, (u64) seg->base, (u32) seg->limit,
		(u8) seg->type, seg->present, seg->dpl, seg->db, seg->s, seg->l, seg->g, seg->avl);
}

void kvm_cpu__show_registers(struct kvm_cpu *vcpu)
{
	unsigned long cr0, cr2, cr3;
	unsigned long cr4, cr8;
	unsigned long rax, rbx, rcx;
	unsigned long rdx, rsi, rdi;
	unsigned long rbp,  r8,  r9;
	unsigned long r10, r11, r12;
	unsigned long r13, r14, r15;
	unsigned long rip, rsp;
	struct kvm_sregs sregs;
	unsigned long rflags;
	struct kvm_regs regs;
	int i;

	if (ioctl(vcpu->vcpu_fd, KVM_GET_REGS, &regs) < 0)
		die("KVM_GET_REGS failed");

	rflags = regs.rflags;

	rip = regs.rip; rsp = regs.rsp;
	rax = regs.rax; rbx = regs.rbx; rcx = regs.rcx;
	rdx = regs.rdx; rsi = regs.rsi; rdi = regs.rdi;
	rbp = regs.rbp; r8  = regs.r8;  r9  = regs.r9;
	r10 = regs.r10; r11 = regs.r11; r12 = regs.r12;
	r13 = regs.r13; r14 = regs.r14; r15 = regs.r15;

	dprintf(debug_fd, "\n Registers:\n");
	dprintf(debug_fd,   " ----------\n");
	dprintf(debug_fd, " rip: %016lx   rsp: %016lx flags: %016lx\n", rip, rsp, rflags);
	dprintf(debug_fd, " rax: %016lx   rbx: %016lx   rcx: %016lx\n", rax, rbx, rcx);
	dprintf(debug_fd, " rdx: %016lx   rsi: %016lx   rdi: %016lx\n", rdx, rsi, rdi);
	dprintf(debug_fd, " rbp: %016lx    r8: %016lx    r9: %016lx\n", rbp, r8,  r9);
	dprintf(debug_fd, " r10: %016lx   r11: %016lx   r12: %016lx\n", r10, r11, r12);
	dprintf(debug_fd, " r13: %016lx   r14: %016lx   r15: %016lx\n", r13, r14, r15);

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
		die("KVM_GET_REGS failed");

	cr0 = sregs.cr0; cr2 = sregs.cr2; cr3 = sregs.cr3;
	cr4 = sregs.cr4; cr8 = sregs.cr8;

	dprintf(debug_fd, " cr0: %016lx   cr2: %016lx   cr3: %016lx\n", cr0, cr2, cr3);
	dprintf(debug_fd, " cr4: %016lx   cr8: %016lx\n", cr4, cr8);
	dprintf(debug_fd, "\n Segment registers:\n");
	dprintf(debug_fd,   " ------------------\n");
	dprintf(debug_fd, " register  selector  base              limit     type  p dpl db s l g avl\n");
	print_segment("cs ", &sregs.cs);
	print_segment("ss ", &sregs.ss);
	print_segment("ds ", &sregs.ds);
	print_segment("es ", &sregs.es);
	print_segment("fs ", &sregs.fs);
	print_segment("gs ", &sregs.gs);
	print_segment("tr ", &sregs.tr);
	print_segment("ldt", &sregs.ldt);
	print_dtable("gdt", &sregs.gdt);
	print_dtable("idt", &sregs.idt);

	dprintf(debug_fd, "\n APIC:\n");
	dprintf(debug_fd,   " -----\n");
	dprintf(debug_fd, " efer: %016llx  apic base: %016llx  nmi: %s\n",
		(u64) sregs.efer, (u64) sregs.apic_base,
		(vcpu->kvm->nmi_disabled ? "disabled" : "enabled"));

	dprintf(debug_fd, "\n Interrupt bitmap:\n");
	dprintf(debug_fd,   " -----------------\n");
	for (i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++)
		dprintf(debug_fd, " %016llx", (u64) sregs.interrupt_bitmap[i]);
	dprintf(debug_fd, "\n");
}

#define MAX_SYM_LEN 128

void kvm_cpu__show_code(struct kvm_cpu *vcpu)
{
	unsigned int code_bytes = 64;
	unsigned int code_prologue = 43;
	unsigned int code_len = code_bytes;
	char sym[MAX_SYM_LEN] = SYMBOL_DEFAULT_UNKNOWN, *psym;
	unsigned char c;
	unsigned int i;
	u8 *ip;

	if (ioctl(vcpu->vcpu_fd, KVM_GET_REGS, &vcpu->regs) < 0)
		die("KVM_GET_REGS failed");

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &vcpu->sregs) < 0)
		die("KVM_GET_SREGS failed");

	ip = guest_flat_to_host(vcpu->kvm, ip_to_flat(vcpu, vcpu->regs.rip) - code_prologue);

	dprintf(debug_fd, "\n Code:\n");
	dprintf(debug_fd,   " -----\n");

	psym = symbol_lookup(vcpu->kvm, vcpu->regs.rip, sym, MAX_SYM_LEN);
	if (IS_ERR(psym))
		dprintf(debug_fd,
			"Warning: symbol_lookup() failed to find symbol "
			"with error: %ld\n", PTR_ERR(psym));

	dprintf(debug_fd, " rip: [<%016lx>] %s\n\n", (unsigned long) vcpu->regs.rip, sym);

	for (i = 0; i < code_len; i++, ip++) {
		if (!host_ptr_in_ram(vcpu->kvm, ip))
			break;

		c = *ip;

		if (ip == guest_flat_to_host(vcpu->kvm, ip_to_flat(vcpu, vcpu->regs.rip)))
			dprintf(debug_fd, " <%02x>", c);
		else
			dprintf(debug_fd, " %02x", c);
	}

	dprintf(debug_fd, "\n");

	dprintf(debug_fd, "\n Stack:\n");
	dprintf(debug_fd,   " ------\n");
	dprintf(debug_fd, " rsp: [<%016lx>] \n", (unsigned long) vcpu->regs.rsp);
	kvm__dump_mem(vcpu->kvm, vcpu->regs.rsp, 32, debug_fd);
}

void kvm_cpu__show_page_tables(struct kvm_cpu *vcpu)
{
	u64 *pte1;
	u64 *pte2;
	u64 *pte3;
	u64 *pte4;

	if (!is_in_protected_mode(vcpu)) {
		dprintf(debug_fd, "\n Page Tables:\n");
		dprintf(debug_fd, " ------\n");
		dprintf(debug_fd, " Not in protected mode\n");
		return;
	}

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &vcpu->sregs) < 0)
		die("KVM_GET_SREGS failed");

	pte4 = guest_flat_to_host(vcpu->kvm, vcpu->sregs.cr3);
	if (!host_ptr_in_ram(vcpu->kvm, pte4))
		return;

	pte3 = guest_flat_to_host(vcpu->kvm, (*pte4 & ~0xfff));
	if (!host_ptr_in_ram(vcpu->kvm, pte3))
		return;

	pte2 = guest_flat_to_host(vcpu->kvm, (*pte3 & ~0xfff));
	if (!host_ptr_in_ram(vcpu->kvm, pte2))
		return;

	pte1 = guest_flat_to_host(vcpu->kvm, (*pte2 & ~0xfff));
	if (!host_ptr_in_ram(vcpu->kvm, pte1))
		return;

	dprintf(debug_fd, "\n Page Tables:\n");
	dprintf(debug_fd, " ------\n");
	if (*pte2 & (1 << 7))
		dprintf(debug_fd, " pte4: %016llx   pte3: %016llx"
			"   pte2: %016llx\n",
			*pte4, *pte3, *pte2);
	else
		dprintf(debug_fd, " pte4: %016llx  pte3: %016llx   pte2: %016"
			"llx   pte1: %016llx\n",
			*pte4, *pte3, *pte2, *pte1);
}

void kvm_cpu__arch_nmi(struct kvm_cpu *cpu)
{
	struct kvm_lapic_state klapic;
	struct local_apic *lapic = (void *)&klapic;

	if (ioctl(cpu->vcpu_fd, KVM_GET_LAPIC, &klapic) != 0)
		return;

	if (lapic->lvt_lint1.mask)
		return;

	if (lapic->lvt_lint1.delivery_mode != APIC_MODE_NMI)
		return;

	ioctl(cpu->vcpu_fd, KVM_NMI);
}
