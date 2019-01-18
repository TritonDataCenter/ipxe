/*
 * Parts copyright Michael Brown <mbrown@fensystems.co.uk>
 *
 * Copyright (c) 2019, Joyent, Inc.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

/* CR0: protection enabled */
#define CR0_PE ( 1 << 0 )

/* CR0: paging */
#define CR0_PG ( 1 << 31 )

/* CR4: physical address extensions */
#define CR4_PSE ( 1 << 4 )
#define CR4_PAE ( 1 << 5 )
#define CR4_PGE ( 1 << 7 )

/* Extended feature enable MSR (EFER) */
#define MSR_EFER 0xc0000080

/* EFER: long mode enable */
#define EFER_LME ( 1 << 8 )

#define GDTSEL_CODE 0x8
#define GDTSEL_DATA 0x10

/*
 * This is really "if EFI", but that's not trivially available.
 */
#ifdef __x86_64__

	.section ".text", "ax", @progbits

	/*
	 * %rdi -> multiboot2 magic
	 * %rsi -> multiboot info pointer
	 * %rdx -> entry address (32 bits)
	 *
	 *
	 * We need to transition from our 64-bit environment into the one
	 * defined by the multiboot2 spec, section 3.3. Namely, drop down to
	 * 32-bit protected mode with a basic GDT, paging disabled, interrupts
	 * off, and
	 *
	 * %eax -> multiboot2 magic
	 * %ebx -> multiboot info pointer (physical)
	 */
	.align 16
	.globl multiboot2_entry

multiboot2_entry:
	cli

	movq	%rsi, %rbx /* mb2 infop */
	movq	%rdx, %rsi /* entry address */

	/* Load the mb2-mandated code and data segments.  */
	leaq	entry_gdt_base(%rip), %rcx
	leaq	entry_gdt(%rip), %rax
	movq	%rax, (%rcx)

	leaq	entry_gdtr(%rip), %rax
	lgdt	(%rax)

	/* Load our new %cs. */
	ljmp	*newcs_vector

	.code32
newcs:

	movw	$GDTSEL_DATA, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss

	/* Disable paging */
	movl	%cr0, %eax
	andl	$~CR0_PG, %eax
	movl	%eax, %cr0

	movl	%cr4, %eax
	andb	$~(CR4_PAE | CR4_PGE | CR4_PSE), %al
	movl	%eax, %cr4

	/* Disable long mode (clobbers %eax, %edx) */
	movl	$MSR_EFER, %ecx
	rdmsr
	andw	$~EFER_LME, %ax
	wrmsr

	/* %ebx still has our infop */
	movl	%edi, %eax
	jmp	*%esi

	.data

newcs_vector:
	.long	newcs, GDTSEL_CODE

	.align 16
entry_gdt:
	/* null entry */
	.word	0x0, 0x0
	.byte	0x0, 0x0, 0x0, 0x0

	/* 32 bit protected mode code segment */
	.word	0xffff, 0x0
	.byte	0x0, 0x9f, 0xcf, 0x0

	/* 32 bit protected mode data segment */
	.word	0xffff, 0x0
	.byte	0x0, 0x93, 0xcf, 0x0

entry_gdt_end:
	.equ	entry_gdt_length, entry_gdt_end - entry_gdt

	.align 16
entry_gdtr:
	.word entry_gdt_length - 1
entry_gdt_base:
	.quad 0

#endif /* __x86_64__ */
