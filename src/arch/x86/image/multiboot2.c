/*
 * Copyright (C) 2016 Star Lab Corp.
 * Copyright (c) 2019, Joyent, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Multiboot2 image format
 *
 * An Illumos kernel is not an EFI image, and multiboot1 cannot load under
 * UEFI.  Thus, multiboot2 is the only hope we have when in UEFI. The format is
 * similar to that of multiboot1.
 *
 * This implementation is certainly incomplete - aside from the lack of legacy
 * BIOS support - but it's sufficient.
 */

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <multiboot2.h>
#include <ipxe/uaccess.h>
#include <ipxe/image.h>
#include <ipxe/segment.h>
#include <ipxe/io.h>
#include <ipxe/init.h>
#include <ipxe/features.h>
#include <ipxe/umalloc.h>
#include <ipxe/uri.h>
#include <ipxe/version.h>

FEATURE ( FEATURE_IMAGE, "MBOOT2", DHCP_EB_FEATURE_MULTIBOOT2, 1 );

#ifdef EFIAPI

#include <ipxe/efi/efi.h>

#define BIB_MAX_SIZE 4096
#define	BIB_ADDR(mb2) ((void *)&((mb2)->bib[(mb2)->bib_offset]))
#define	BIB_SPACE(mb2, tagsize) (BIB_MAX_SIZE - (mb2)->bib_offset - (tagsize))

struct mb2_image_header {
	struct multiboot_header mb;
	size_t file_offset;
};

struct mb2_entry {
	enum entry_type {
		ENTRY_I386,
		ENTRY_EFI32,
		ENTRY_EFI64
	} type;
	uint32_t addr;
};

struct mb2 {
	struct image *image;
	struct mb2_image_header image_hdr;

	/* Tag information from image. */

	struct multiboot_header_tag_address load;
	struct mb2_entry entry;
	int keep_boot_services;

	union {
		uint64_t bib_align;
		char bib[BIB_MAX_SIZE];
	};

	size_t bib_offset;
};

struct mb2 mb2;

static int multiboot2_find_header ( struct image *image,
				    struct mb2_image_header *hdr ) {
	uint32_t buf[64];
	size_t offset;
	unsigned int buf_idx;
	uint32_t checksum;

	/*
	 * Scan through first MULTIBOOT_SEARCH of image file 256 bytes at
	 * a time.  (Use the buffering to avoid the overhead of a
	 * copy_from_user() for every dword.)
	 */

	for ( offset = 0 ; offset < MULTIBOOT_SEARCH ;
	      offset += sizeof ( buf[0] ) ) {
		if ( offset > image->len )
			break;

		/* Refill buffer if applicable */
		buf_idx = ( ( offset % sizeof ( buf ) ) / sizeof ( buf[0] ) );
		if ( buf_idx == 0 ) {
			copy_from_user ( buf, image->data, offset,
					 sizeof ( buf ) );
		}

		if ( buf[buf_idx] != MULTIBOOT2_HEADER_MAGIC )
			continue;

		copy_from_user ( &hdr->mb, image->data, offset,
				 sizeof ( hdr->mb ) );

		checksum = ( hdr->mb.magic + hdr->mb.architecture +
			     hdr->mb.header_length + hdr->mb.checksum );
		if ( checksum != 0 )
			continue;

		if ( hdr->mb.architecture != MULTIBOOT_ARCHITECTURE_I386 )
			return -ENOEXEC;

		hdr->file_offset = offset;
		return 0;
	}

	/* No multiboot header found */
	return -ENOEXEC;
}

static int multiboot2_inforeq ( struct mb2 *mb2, size_t offset,
				size_t nr_reqs ) {
	size_t i;

	for ( i = 0; i < nr_reqs; i++ ) {
		uint32_t inforeq;

		copy_from_user ( &inforeq, mb2->image->data,
				 offset + ( i * sizeof ( inforeq ) ),
				 sizeof ( inforeq ) );

		DBGC ( mb2->image, "MULTIBOOT2 %p inforeq tag %d\n",
		       mb2->image, inforeq );

		/*
		 * Note that we don't actually supply framebuffer or bootdev
		 * information, but we acknowledge the request.
		 */

		switch ( inforeq ) {
		case MULTIBOOT_TAG_TYPE_BASIC_MEMINFO:
		case MULTIBOOT_TAG_TYPE_MMAP:
		case MULTIBOOT_TAG_TYPE_CMDLINE:
		case MULTIBOOT_TAG_TYPE_MODULE:
		case MULTIBOOT_TAG_TYPE_BOOTDEV:
		case MULTIBOOT_TAG_TYPE_FRAMEBUFFER:
			continue;

		default:
			printf ( "unsupported inforeq tag %d\n", inforeq );
			return -ENOTSUP;
		}
	}

	return 0;
}

static int multiboot2_process_tag ( struct mb2 *mb2,
				    struct multiboot_header_tag *tag,
				    size_t offset ) {
	struct multiboot_header_tag_entry_address entry_tag = { 0 };
	int rc = 0;

	switch ( tag->type ) {
	case MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST: {
		size_t nr_inforeqs = ( tag->size - sizeof ( *tag ) ) /
				       sizeof ( uint32_t );

		rc = multiboot2_inforeq ( mb2, offset + sizeof ( *tag ),
					  nr_inforeqs );
		if ( rc != 0 )
			return rc;
		break;
	}

	case MULTIBOOT_HEADER_TAG_ADDRESS:

		copy_from_user ( &mb2->load, mb2->image->data,
				 offset, tag->size );

		DBGC ( mb2->image, "address tag: header_addr 0x%x, "
		    "load_addr 0x%x, load_end_addr 0x%x "
		    "bss_end_addr 0x%x\n", mb2->load.header_addr,
		    mb2->load.load_addr, mb2->load.load_end_addr,
		    mb2->load.bss_end_addr );
		break;

	case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS: {
		copy_from_user ( &entry_tag, mb2->image->data,
				 offset, tag->size );

		mb2->entry.type = ENTRY_I386;
		mb2->entry.addr = entry_tag.entry_addr;
		break;
	}

	case MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS:
		/* We should be OK to safely ignore this tag. */
		break;

	case MULTIBOOT_HEADER_TAG_FRAMEBUFFER:
		/* Should be able to ignore this. */
		break;

	case MULTIBOOT_HEADER_TAG_MODULE_ALIGN:
		/* Modules are umalloc()ed and hence always page-aligned. */
		break;

	case MULTIBOOT_HEADER_TAG_EFI_BS:
		mb2->keep_boot_services = 1;
		break;

	case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI32:
		printf ( "unsupported tag ENTRY_ADDRESS_EFI32" );
		rc = -ENOTSUP;
		break;

	case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI64: {
		copy_from_user ( &entry_tag, mb2->image->data,
				 offset, tag->size );

		mb2->entry.type = ENTRY_EFI64;
		mb2->entry.addr = entry_tag.entry_addr;
		break;
	}

	case MULTIBOOT_HEADER_TAG_RELOCATABLE:
		/* We will always map at the requested address. */
		break;

	default:
		printf ( "unknown header tag %x\n", tag->type );
		rc = -ENOTSUP;
		break;
	}

	return rc;
}

/*
 * Process the image's tags.
 */
static int multiboot2_process_tags ( struct mb2 *mb2 ) {
	size_t offset = mb2->image_hdr.file_offset +
			sizeof ( struct multiboot_header );
	size_t end_offset = offset + mb2->image_hdr.mb.header_length;
	int saw_entry = 0;
	int saw_load = 0;
	int rc;

	while ( offset < end_offset ) {
		struct multiboot_header_tag tag;

		copy_from_user ( &tag, mb2->image->data,
				 offset, sizeof ( tag ) );

		DBGC ( mb2->image, "MULTIBOOT2 %p (offset: 0x%zx) tag type: %x "
		       "flags: %x size: %d\n", mb2->image,
		       offset - mb2->image_hdr.file_offset,
		       tag.type, tag.flags, tag.size );

		switch ( tag.type ) {
		case MULTIBOOT_HEADER_TAG_END:
			if (!saw_load) {
				printf ( "%p missing ADDRESS\n", mb2->image );
				return -ENOEXEC;
			}
			if (!saw_entry) {
				printf ( "%p missing entry\n", mb2->image );
				return -ENOEXEC;
			}
			return 0;
		case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI64:
		case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS:
			saw_entry = 1;
			break;
		case MULTIBOOT_HEADER_TAG_ADDRESS:
			saw_load = 1;
			break;
		}

		rc = multiboot2_process_tag ( mb2, &tag, offset );

		if ( rc != 0 )
			return rc;

		offset += tag.size + (MULTIBOOT_TAG_ALIGN - 1);
		offset = offset & ~(MULTIBOOT_TAG_ALIGN - 1);
	}

	printf ( "%p missing end tag\n", mb2->image );
	return -ENOTSUP;
}

/*
 * Load the image at the requested load address.
 */
static int multiboot2_load ( struct mb2 *mb2 ) {
	struct multiboot_header_tag_address *load = &mb2->load;
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_PHYSICAL_ADDRESS buf_pa;
	size_t file_offset;
	size_t buf_offset;
	EFI_STATUS efirc;
	userptr_t buffer;
	size_t filesz;
	size_t memsz;

	// FIXME: multiboot1 has "image->len - file_offset" here ???
	filesz = ( load->load_end_addr ?
		   ( load->load_end_addr - load->load_addr ) :
		   mb2->image->len );

	memsz = ( load->bss_end_addr ?
		  ( load->bss_end_addr - load->load_addr ) : filesz );

	/*
	 * Our buffer must be page-aligned.
	 */
	buf_pa = load->load_addr & ~EFI_PAGE_MASK;
	buf_offset = load->load_addr & EFI_PAGE_MASK;

	efirc = bs->AllocatePages ( AllocateAddress, EfiLoaderData,
				    EFI_SIZE_TO_PAGES ( memsz + buf_offset ),
				    &buf_pa );

	if ( efirc != 0 ) {
		printf ( "Failed to allocate pages for kernel (%d) "
			 "pa: 0x%llx size: 0x%zx\n", (int)efirc,
			 buf_pa, memsz + buf_offset );
		return -EEFI ( efirc );
	}

	buffer = phys_to_user ( (physaddr_t)buf_pa );
	file_offset = ( mb2->image_hdr.file_offset -
			load->header_addr + load->load_addr );

	DBGC ( mb2->image, "MULTIBOOT2 %s: buffer 0x%lx:0x%zx filesz 0x%zx "
	       "memsz 0x%zx file_offset 0x%zx\n", __func__, buffer, buf_offset,
	       filesz, memsz, file_offset );

	memcpy_user ( buffer, buf_offset,
		      mb2->image->data, file_offset, filesz );
	memset_user ( buffer, buf_offset + filesz, 0, ( memsz - filesz ) );

	return 0;
}

static void align_tag_offset ( size_t *offset ) {
	if ( ( *offset & 7 ) != 0 )
		*offset = ( ( *offset + 8 ) & ~7 );
}

// FIXME: in general, check we have space

static int multiboot2_add_cmdline ( struct mb2 *mb2 ) {
	struct multiboot_tag_string *cmdline = BIB_ADDR ( mb2 );
	size_t remaining = BIB_SPACE ( mb2, sizeof ( *cmdline ) );
	char *buf = cmdline->string;
	size_t len;

	DBGC ( mb2->image, "MULTIBOOT2 CMDLINE at 0x%zx\n", mb2->bib_offset );
	cmdline->type = MULTIBOOT_TAG_TYPE_CMDLINE;
	cmdline->size = sizeof ( *cmdline );

	len = ( format_uri ( mb2->image->uri, buf, remaining ) + 1 );
	buf += len;
	remaining -= len;
	cmdline->size += len;

	/* Copy command line to base memory buffer, if present */
	if ( mb2->image->cmdline != NULL ) {
		buf--;
		cmdline->size--;
		remaining++;
		len = snprintf ( buf, remaining, " %s",
		      mb2->image->cmdline ) + 1;
		cmdline->size += len;
	}

	mb2->bib_offset += cmdline->size;
	align_tag_offset ( &mb2->bib_offset );
	return 0;
}

static int multiboot2_add_bootloader ( struct mb2 *mb2 ) {
	struct multiboot_tag_string *bootloader = BIB_ADDR ( mb2 );
	size_t remaining = BIB_SPACE ( mb2, sizeof ( *bootloader ) );
	char *buf = bootloader->string;
	size_t len;

	len = snprintf ( buf, remaining, "iPXE %s", product_version ) + 1;

	DBGC ( mb2->image, "MULTIBOOT2 BOOT_LOADER_NAME at 0x%zx\n",
	       mb2->bib_offset );
	bootloader->type = MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME;
	bootloader->size = len + sizeof ( *bootloader );

	mb2->bib_offset += bootloader->size;
	align_tag_offset ( &mb2->bib_offset );
	return 0;
}

static int multiboot2_add_modules ( struct mb2 * mb2 ) {
	struct multiboot_tag_module *module;
	struct image *module_image;
	size_t remaining;
	size_t len;
	char *buf;

	/* Add each image as a multiboot module */
	for_each_image ( module_image ) {

		/* Do not include kernel image itself as a module */
		if ( module_image == mb2->image )
			continue;

		/*
		 * FIXME: loader allocates in chunks, then relocates after
		 * exiting boot services. ipxe has no support for this; we might
		 * well hit the issue where we can't actually allocate enough
		 * pages for our huge boot archive. This is system-dependent...
		 */

		/* Add module to list */
		DBGC ( mb2->image, "MULTIBOOT2 module %s at 0x%zx\n",
		       module_image->name, mb2->bib_offset );
		module = BIB_ADDR ( mb2 );
		module->type = MULTIBOOT_TAG_TYPE_MODULE;
		module->size = sizeof ( *module );
		module->mod_start = user_to_phys ( module_image->data, 0 );
		module->mod_end = user_to_phys ( module_image->data,
						 module_image->len );

		buf = module->cmdline;
		remaining = BIB_SPACE ( mb2, sizeof ( *module ) );

		len = ( format_uri ( module_image->uri, buf, remaining ) + 1 );
		if ( len > remaining )
			len = remaining;
		buf += len;
		remaining -= len;
		module->size += len;

		/* Copy command line to base memory buffer, if present */
		if ( module_image->cmdline != NULL ) {
			buf--;
			module->size--;
			remaining++;
			len = snprintf ( buf, remaining, " %s",
				module_image->cmdline ) + 1;
			if ( len > remaining )
				len = remaining;
			module->size += len;
		}

		mb2->bib_offset += module->size;
		align_tag_offset ( &mb2->bib_offset );

		DBGC ( mb2->image, "MULTIBOOT2 %p module %s is [%x,%x): %s\n",
		       mb2->image, module_image->name, module->mod_start,
		       module->mod_end, module->cmdline );
	}

	return 0;
}

#define EM_ENTRY(em, i) ((EFI_MEMORY_DESCRIPTOR *)	\
	((em)->mmap_buf + (i) * ((em)->descr_size)))

static char efi_mmap_buf[EFI_PAGE_SIZE];

struct efi_mmap {
	char *mmap_buf;
	size_t nr_descrs;
	size_t descr_size;
	size_t descr_version;
	UINTN key;
};

static EFI_STATUS get_efi_mmap ( struct efi_mmap *mp ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	UINTN size = sizeof ( efi_mmap_buf );
	UINT32 descr_version;
	EFI_STATUS efirc;
	UINTN descr_size;
	UINTN key;

	efirc = bs->GetMemoryMap ( &size, (EFI_MEMORY_DESCRIPTOR *)efi_mmap_buf,
				   &key, &descr_size, &descr_version );

	if ( efirc != 0 ) {
		printf ( "GetMemoryMap failed with %d\n", (int)efirc );
		return efirc;
	}

	mp->mmap_buf = efi_mmap_buf;
	mp->nr_descrs = size / descr_size;
	mp->descr_size = descr_size;
	mp->descr_version = descr_version;
	mp->key = key;
	return EFI_SUCCESS;
}

static multiboot_uint32_t
convert_efi_type ( EFI_MEMORY_TYPE type )
{
	switch ( type ) {
	case EfiReservedMemoryType:
		return MULTIBOOT_MEMORY_RESERVED;

	case EfiLoaderCode:
	case EfiLoaderData:
	case EfiBootServicesCode:
	case EfiBootServicesData:
		return MULTIBOOT_MEMORY_AVAILABLE;

	case EfiRuntimeServicesCode:
	case EfiRuntimeServicesData:
		return MULTIBOOT_MEMORY_RESERVED;

	case EfiConventionalMemory:
		return MULTIBOOT_MEMORY_AVAILABLE;

	// FIXME: loader doesn't do this: why?
	case EfiUnusableMemory:
		return MULTIBOOT_MEMORY_BADRAM;

	case EfiACPIReclaimMemory:
		return MULTIBOOT_MEMORY_ACPI_RECLAIMABLE;

	case EfiACPIMemoryNVS:
		return MULTIBOOT_MEMORY_NVS;

	case EfiMemoryMappedIO:
	case EfiMemoryMappedIOPortSpace:
	case EfiPalCode:
		return MULTIBOOT_MEMORY_RESERVED;

	default:
		printf ( "unknown memory type %d\n", type );
		return MULTIBOOT_MEMORY_RESERVED;
	}
}

/**
 *
 * Convert an EFI mmap into a traditional multiboot structure.  As the types
 * are less specific, we will merge adjacent ranges that have the same multiboot
 * type.
 */
static ssize_t multiboot2_build_mmap ( struct image *image,
				       struct efi_mmap *em,
				       struct multiboot_mmap_entry *mmap,
				       size_t bufsize) {
	struct multiboot_mmap_entry *lastme = NULL;
	size_t nr = 0;
	size_t i;

	for ( i = 0; i < em->nr_descrs; i++ ) {
		EFI_MEMORY_DESCRIPTOR *d = EM_ENTRY ( em, i );
		multiboot_uint32_t mt = convert_efi_type ( d->Type );
		struct multiboot_mmap_entry *me = &mmap[nr];

		DBGC ( image, "EM[%zd]: PhysicalStart 0x%llx "
		       "NumberOfPages %lld Type 0x%d\n", i, d->PhysicalStart,
		       d->NumberOfPages, d->Type );

		if ( lastme != NULL && mt== lastme->type &&
			d->PhysicalStart == lastme->addr + lastme->len ) {
			lastme->len += d->NumberOfPages << EFI_PAGE_SHIFT;
			continue;
		}

		if ( bufsize < ( ++nr ) * sizeof ( *me ) ) {
			printf ( "not enough space for mmap (%lx < %lx)\n",
			    bufsize, nr * sizeof ( *me ) );
			return -ENOMEM;
		}

		me->addr = d->PhysicalStart;
		me->len =  d->NumberOfPages << EFI_PAGE_SHIFT;
		me->type = mt;
		me->zero = 0;
		lastme = me;
	}

	return nr * sizeof ( *mmap );
}

/**
 *
 * Supply both MMAP tag type contents.  They're duplicating information, but at
 * least Illumos doesn't parse MULTIBOOT_TAG_TYPE_EFI_MMAP, so we must supply
 * MULTIBOOT_TAG_TYPE_MMAP as well.
 */
static int multiboot2_add_mmap ( struct mb2 *mb2 ) {
	struct multiboot_tag_efi_mmap *emt;
	struct multiboot_tag_mmap *mt;
	struct efi_mmap em;
	EFI_STATUS efirc;
	ssize_t size;

	DBGC ( mb2->image, "MULTIBOOT2 EFI_MMAP at 0x%zx\n", mb2->bib_offset );

 	emt = BIB_ADDR ( mb2 );
	emt->type = MULTIBOOT_TAG_TYPE_EFI_MMAP;
	emt->descr_size = em.descr_size;
	emt->descr_vers = em.descr_version;

	mb2->bib_offset += sizeof ( *emt );

	if ( ( efirc = get_efi_mmap ( &em ) ) != 0 )
		return -EEFI ( efirc );

	size = em.nr_descrs * em.descr_size;

	memcpy_user ( (userptr_t)mb2->bib, mb2->bib_offset,
		      (userptr_t)em.mmap_buf, 0, size );

	emt->size = sizeof ( *emt ) + size;
	mb2->bib_offset += size;
	align_tag_offset ( &mb2->bib_offset );

	DBGC ( mb2->image, "MULTIBOOT2 MMAP at 0x%zx\n", mb2->bib_offset );

	mt = BIB_ADDR ( mb2 );
	mt->type = MULTIBOOT_TAG_TYPE_MMAP;
	mt->entry_size = sizeof ( struct multiboot_mmap_entry );
	mt->entry_version = 0;

	mb2->bib_offset += sizeof ( *mt );

	size = multiboot2_build_mmap ( mb2->image, &em, BIB_ADDR ( mb2 ),
				       BIB_SPACE ( mb2, 0 ) );

        if ( size < 0 )
		return (int)size;

	mt->size = sizeof ( *mt ) + size;
	mb2->bib_offset += size;
	align_tag_offset ( &mb2->bib_offset );

	return 0;
}

/*
 * To successfully exit boot services, we must pass a non-stale mmap key.
 * However, it's possible for EVT_SIGNAL_EXIT_BOOT_SERVICES handlers to
 * themselves do allocations.  They should only be called once, so we'll try
 * twice.
 *
 * The key is also why we need to re-get the mmap immediately before
 * ->ExitBootServices().
 */
static int exit_boot_services ( struct mb2 *mb2 ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	struct efi_mmap em;
	EFI_STATUS efirc;
	int tries = 0;

again:
	if ( ( efirc = get_efi_mmap ( &em ) ) != 0 )
		return -EEFI ( efirc );

	efirc = bs->ExitBootServices ( efi_image_handle, (UINTN)em.key );

	if ( efirc == EFI_INVALID_PARAMETER && tries++ == 0 )
		goto again;

	if ( efirc != 0 ) {
		DBGC ( mb2->image, "ExitBootServices() failed with %d\n",
		       (int)efirc );
		return -EEFI ( efirc );
	}

	return 0;
}

void multiboot2_boot ( uint32_t *bib, uint32_t entry ) {
	__asm__ __volatile__ ( "push %%rbp\n\t"
			       "call *%%rdi\n\t"
			       "pop %%rbp\n\t"
			       : : "a" ( MULTIBOOT2_BOOTLOADER_MAGIC ),
                                   "b" ( bib ), "D" ( entry )
			       : "rcx", "rdx", "rsi", "memory" );
}

static int multiboot2_exec ( struct image *image ) {
	struct multiboot_tag_load_base_addr *load_base_addr_tag;
	struct multiboot_tag_efi64_ih *tag_efi64_ih;
	struct multiboot_tag_efi64 *tag_efi64;
	struct multiboot_tag *tag;
	uint32_t *total_sizep;
	int rc;

	mb2.image = image;

	if ( ( rc = multiboot2_find_header ( mb2.image,
					     &mb2.image_hdr ) ) != 0 ) {
		DBGC ( image, "MULTIBOOT2 %p has no multiboot header\n",
		       image );
		return rc;
	}

	if ( ( rc = multiboot2_process_tags ( &mb2 ) ) != 0 )
		return rc;

	if ( ( rc = multiboot2_load ( &mb2 ) ) != 0) {
		printf ( "MULTIBOOT2 %p: could not load (%d)\n", image, rc );
		return rc;
	}

	total_sizep = BIB_ADDR ( &mb2 );
	mb2.bib_offset += sizeof ( *total_sizep );

	/* reserved field */
	mb2.bib_offset += sizeof ( uint32_t );

	DBGC ( image, "MULTIBOOT2 LOAD_BASE_ADDR at 0x%zx\n", mb2.bib_offset );
	load_base_addr_tag = BIB_ADDR ( &mb2 );
	load_base_addr_tag->type = MULTIBOOT_TAG_TYPE_LOAD_BASE_ADDR;
	load_base_addr_tag->size = sizeof ( *load_base_addr_tag );
	load_base_addr_tag->load_base_addr = mb2.load.load_addr;
	mb2.bib_offset += load_base_addr_tag->size;
	align_tag_offset ( &mb2.bib_offset );

	DBGC ( image, "MULTIBOOT2 EFI64_IH at 0x%zx\n", mb2.bib_offset );
	tag_efi64_ih = BIB_ADDR ( &mb2 );
	tag_efi64_ih->type = MULTIBOOT_TAG_TYPE_EFI64_IH;
	tag_efi64_ih->size = sizeof ( *tag_efi64_ih );
	tag_efi64_ih->pointer = (multiboot_uint64_t)efi_image_handle;
	mb2.bib_offset += tag_efi64_ih->size;
	align_tag_offset ( &mb2.bib_offset );

	DBGC ( image, "MULTIBOOT2 EFI64 at 0x%zx\n", mb2.bib_offset );
	tag_efi64 = BIB_ADDR ( &mb2 );
	tag_efi64->type = MULTIBOOT_TAG_TYPE_EFI64;
	tag_efi64->size = sizeof ( *tag_efi64 );
	tag_efi64->pointer = (multiboot_uint64_t)efi_systab;
	mb2.bib_offset += tag_efi64->size;
	align_tag_offset ( &mb2.bib_offset );

	if ( mb2.keep_boot_services ) {
		DBGC ( image, "MULTIBOOT2 EFI_BS at 0x%zx\n", mb2.bib_offset );
		tag = BIB_ADDR ( &mb2 );
		tag->type = MULTIBOOT_TAG_TYPE_EFI_BS;
		tag->size = sizeof ( *tag );
		mb2.bib_offset += tag->size;
		align_tag_offset ( &mb2.bib_offset );
	}

	if ( ( rc = multiboot2_add_mmap ( &mb2 ) ) != 0 )
		return rc;

	if ( ( rc = multiboot2_add_cmdline ( &mb2 ) ) != 0 )
		return rc;

	if ( ( rc = multiboot2_add_bootloader ( &mb2 ) ) != 0 )
		return rc;

	if ( ( rc = multiboot2_add_modules ( &mb2 ) ) != 0 )
		return rc;

	/* Terminate the tags */
	tag = BIB_ADDR ( &mb2 );
	tag->type = 0;
	tag->size = sizeof ( *tag );
	mb2.bib_offset += tag->size;

	*total_sizep = mb2.bib_offset;

	DBGC ( image, "MULTIBOOT2 %p BIB is %d bytes\n", image, *total_sizep );
	DBGC ( image, "MULTIBOOT2 %p starting execution at %x\n",
	       image, mb2.entry.addr );

	if ( !mb2.keep_boot_services ) {
		if ( ( rc = exit_boot_services ( &mb2 ) ) != 0 )
			return rc;
	} else {
		/*
		 * Multiboot images may not return and have no callback
		 * interface, so shut everything down prior to booting the OS.
		 */
		shutdown_boot ( );
	}

	/* Jump to OS with flat physical addressing */

	if ( mb2.entry.type == ENTRY_EFI64 ) {
		multiboot2_boot ( (uint32_t *)mb2.bib,
				   (uint32_t)mb2.entry.addr );
	} else {
		extern void multiboot2_tramp ( uint32_t, uint64_t, uint64_t );

		multiboot2_tramp ( MULTIBOOT2_BOOTLOADER_MAGIC,
				   (uint64_t)mb2.bib, mb2.entry.addr );
	}

	DBGC ( image, "MULTIBOOT2 %p returned\n", mb2.image );

	/* It isn't safe to continue after calling shutdown() */
	while ( 1 ) {}

	return -ECANCELED;  /* -EIMPOSSIBLE, anyone? */
}

static int multiboot2_probe ( struct image *image ) {
	struct mb2_image_header hdr;
	int rc;

	if ( ( rc = multiboot2_find_header ( image, &hdr ) ) != 0 ) {
		DBGC ( image, "MULTIBOOT2 %p has no multiboot2 header\n",
			   image );
		return rc;
	}

	DBGC ( image, "MULTIBOOT2 %p found header at offset %zx "
	       "with architecture %08x and header_length %d\n", image,
	       hdr.file_offset, hdr.mb.architecture, hdr.mb.header_length );

	return 0;
}

#else /* EFIAPI */

static int multiboot2_exec ( struct image *image ) {
	return -ENOTSUP;
}

static int multiboot2_probe ( struct image *image ) {
	return -ENOEXEC;
}

#endif

/** Multiboot image type */
struct image_type multiboot2_image_type __image_type ( PROBE_MULTIBOOT2 ) = {
	.name = "Multiboot 2",
	.probe = multiboot2_probe,
	.exec = multiboot2_exec,
};
