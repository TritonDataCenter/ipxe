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

// FIXME: we should make this EFI only

/**
 * @file
 *
 * Multiboot2 image format
 *
 * FIXME
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
#ifdef EFIAPI
#include <ipxe/efi/efi.h>
#endif

FEATURE ( FEATURE_IMAGE, "MBOOT2", DHCP_EB_FEATURE_MULTIBOOT2, 1 );

/**
 * Maximum multiboot2 boot information size
 */
#define MB_MAX_BOOTINFO_SIZE 4096

/** Multiboot2 boot information buffer */
// FIXME add an accesser define
static union {
	uint64_t align;
	char bib[MB_MAX_BOOTINFO_SIZE];
} mb2_bib;

// FIXME: should collate all the stuff in here
/** A multiboot2 header descriptor */
struct multiboot2_header_info {
	/** The actual multiboot2 header */
	struct multiboot_header mb;
	/** Offset of header within the multiboot2 image */
	size_t offset;
};

/**
 * Find multiboot2 header
 *
 * @v image		Multiboot file
 * @v hdr		Multiboot header descriptor to fill in
 * @ret rc		Return status code
 */
static int multiboot2_find_header ( struct image *image,
				    struct multiboot2_header_info *hdr ) {
	uint32_t buf[64];
	size_t offset;
	unsigned int buf_idx;
	uint32_t checksum;

	/* Scan through first MULTIBOOT_SEARCH of image file 256 bytes at a time.
	 * (Use the buffering to avoid the overhead of a
	 * copy_from_user() for every dword.)
	 */
	for ( offset = 0 ; offset < MULTIBOOT_SEARCH ; offset += sizeof ( buf[0] ) ) {
		/* Check for end of image */
		if ( offset > image->len )
			break;
		/* Refill buffer if applicable */
		buf_idx = ( ( offset % sizeof ( buf ) ) / sizeof ( buf[0] ) );
		if ( buf_idx == 0 ) {
			copy_from_user ( buf, image->data, offset,
					 sizeof ( buf ) );
		}
		/* Check signature */
		if ( buf[buf_idx] != MULTIBOOT2_HEADER_MAGIC )
			continue;
		/* Copy header and verify checksum */
		copy_from_user ( &hdr->mb, image->data, offset,
				 sizeof ( hdr->mb ) );
		checksum = ( hdr->mb.magic + hdr->mb.architecture + hdr->mb.header_length +
				 hdr->mb.checksum );
		if ( checksum != 0 )
			continue;

		/* Make sure that the multiboot architecture is x86 */
		if (hdr->mb.architecture != MULTIBOOT_ARCHITECTURE_I386) {
			return -ENOEXEC;
		}

		/* Record offset of multiboot header and return */
		hdr->offset = offset;
		return 0;
	}

	/* No multiboot header found */
	return -ENOEXEC;
}

struct multiboot2_tags {
	int keep_boot_services;

	// FIXME!
	struct multiboot_header_tag_address addr;

	int entry_addr_valid;
	int entry_addr_efi32_valid;
	int entry_addr_efi64_valid;
	int relocatable_valid;

	uint32_t entry_addr;
	uint32_t entry_addr_efi32;
	uint32_t entry_addr_efi64;
	uint32_t reloc_min_addr;
	uint32_t reloc_max_addr;
	uint32_t reloc_align;
	uint32_t reloc_preference;
};

static int multiboot2_validate_inforeq ( struct image *image, size_t offset, size_t num_reqs ) {
	uint32_t inforeq;

	while (num_reqs) {
		copy_from_user ( &inforeq, image->data, offset, sizeof ( inforeq ) );
		offset += sizeof(inforeq);
		num_reqs--;

		DBGC ( image, "MULTIBOOT2 %p info request tag %d\n", image, inforeq);

		switch (inforeq) {
		case MULTIBOOT_TAG_TYPE_BASIC_MEMINFO:
		case MULTIBOOT_TAG_TYPE_MMAP:
		case MULTIBOOT_TAG_TYPE_CMDLINE:
		case MULTIBOOT_TAG_TYPE_MODULE:
		case MULTIBOOT_TAG_TYPE_BOOTDEV: // FIXME?
		case MULTIBOOT_TAG_TYPE_FRAMEBUFFER:
			continue;

		default:
			DBGC ( image, "MULTIBOOT2 %p unsupported info request tag %d\n",
				   image, inforeq );
			return -ENOTSUP;
		}
	}

	return 0;
}

static int multiboot2_validate_tags ( struct image *image, struct multiboot2_header_info *hdr,
	   struct multiboot2_tags *tags ) {
	size_t offset = hdr->offset + sizeof(struct multiboot_header);
	size_t end_offset = offset + hdr->mb.header_length;
	struct multiboot_header_tag tag;

	/* Clear out the multiboot2 tags structure */
	memset(tags, 0, sizeof(*tags));

	while (offset < end_offset) {
		copy_from_user ( &tag, image->data, offset, sizeof ( tag ) );

		DBGC ( image, "MULTIBOOT2 %p (offset: %d) TAG type: %x flags: %x size: %d\n", image,
				(int)(offset - hdr->offset), tag.type, tag.flags, tag.size );

		if (tag.type == MULTIBOOT_HEADER_TAG_END) {
			DBGC ( image, "MULTIBOOT2 %p tag end\n", image );
			return 0;
		}

		switch (tag.type) {
		case MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST:
		{
			size_t num_inforeqs;

			DBGC ( image, "MULTIBOOT2 %p has an information request tag\n",
				   image );

			num_inforeqs = (tag.size - sizeof(tag)) / sizeof(uint32_t);

			if (multiboot2_validate_inforeq ( image, offset + sizeof(tag), num_inforeqs ) != 0) {
				return -ENOTSUP;
			}

			break;
		}
		case MULTIBOOT_HEADER_TAG_ADDRESS:
		{
			struct multiboot_header_tag_address mb_tag = { 0 };

			copy_from_user ( &mb_tag, image->data, offset, tag.size);

			DBGC ( image, "MULTIBOOT2 %p has an address tag\n",
				   image );

			DBGC ( image, "header %x load %x end %x bss_end %x\n",
			    mb_tag.header_addr, mb_tag.load_addr, mb_tag.load_end_addr,
			    mb_tag.bss_end_addr);

			tags->addr = mb_tag;

			break;
		}

		case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS:
		{
			struct multiboot_header_tag_entry_address mb_tag = { 0 };
			copy_from_user ( &mb_tag, image->data, offset, tag.size );

			DBGC ( image, "MULTIBOOT2 %p has an entry address %x\n",
				   image, mb_tag.entry_addr );

			tags->entry_addr_valid = 1;
			tags->entry_addr = mb_tag.entry_addr;
			break;
		}
		case MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS:
			DBGC ( image, "MULTIBOOT2 %p has a console flags tag\n",
				   image );

			/* We should be OK to safely ignore this tag. */
			break;

		case MULTIBOOT_HEADER_TAG_FRAMEBUFFER:
			DBGC ( image, "MULTIBOOT2 %p has a framebuffer tag\n",
				   image );

			/* Should be able to ignore this. */
			break;

		case MULTIBOOT_HEADER_TAG_MODULE_ALIGN:
			DBGC ( image, "MULTIBOOT2 %p has a module align tag\n",
				   image );
			/* Modules are umalloc()ed and hence always page-aligned. */
			break;

		case MULTIBOOT_HEADER_TAG_EFI_BS:
			DBGC ( image, "MULTIBOOT2 %p has a boot services tag\n",
				   image );
			tags->keep_boot_services = 1;
			break;

		// FIXME: we won't really support these two?
		case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI32:
		{
			struct multiboot_header_tag_entry_address mb_tag = { 0 };
			copy_from_user ( &mb_tag, image->data, offset, tag.size );

			DBGC ( image, "MULTIBOOT2 %p has an entry address EFI32 tag\n",
				   image );

			tags->entry_addr_efi32_valid = 1;
			tags->entry_addr_efi32 = mb_tag.entry_addr;
			break;
		}
		case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI64:
		{
			struct multiboot_header_tag_entry_address mb_tag = { 0 };
			copy_from_user ( &mb_tag, image->data, offset, tag.size );

			DBGC ( image, "MULTIBOOT2 %p has an entry address EFI64 tag: %x\n",
				   image, mb_tag.entry_addr );

			tags->entry_addr_efi64_valid = 1;
			tags->entry_addr_efi64 = mb_tag.entry_addr;
			break;
		}
		case MULTIBOOT_HEADER_TAG_RELOCATABLE:
		{
			struct multiboot_header_tag_relocatable mb_tag = { 0 };
			copy_from_user ( &mb_tag, image->data, offset, tag.size );

			DBGC ( image, "MULTIBOOT2 %p has a relocatable tag\n",
				   image );

			// FIXME: don't do anything with these
			tags->relocatable_valid = 1;
			tags->reloc_min_addr = mb_tag.min_addr;
			tags->reloc_max_addr = mb_tag.max_addr;
			tags->reloc_align = mb_tag.align;
			tags->reloc_preference = mb_tag.preference;
			break;
		}
		default:
			DBGC ( image, "MULTIBOOT2 %p unknown tag %x\n",
				   image, tag.type );
			return -ENOTSUP;
		}

		offset += tag.size + (MULTIBOOT_TAG_ALIGN - 1);
		offset = offset & ~(MULTIBOOT_TAG_ALIGN - 1);
	}

	/* If we did not get a MULTIBOOT_HEADER_TAG_END, fail out */
	DBGC ( image, "MULTIBOOT %p missing tag end\n", image );
	return -ENOTSUP;
}

static size_t multiboot2_add_bootloader ( struct image *image, size_t offset ) {
	struct multiboot_tag_string *bootloader = (struct multiboot_tag_string *)&mb2_bib.bib[offset];
	size_t remaining = MB_MAX_BOOTINFO_SIZE - offset - sizeof(*bootloader);
	size_t len;
	char *buf = bootloader->string;

	len = ( snprintf ( buf, remaining, "iPXE %s", product_version ) + 1 /* NUL */ );
	if ( len > remaining )
		len = remaining;

	DBGC ( image, "MULTIBOOT2 %p bootloader: %s\n", image, bootloader->string );

	bootloader->type = MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME;
	bootloader->size = len + sizeof(*bootloader);
	return bootloader->size;
}

static size_t multiboot2_add_cmdline ( struct image *image, size_t offset ) {
	struct multiboot_tag_string *cmdline = (struct multiboot_tag_string *)&mb2_bib.bib[offset];
	size_t remaining = MB_MAX_BOOTINFO_SIZE - offset - sizeof(*cmdline);
	size_t len;
	char *buf = cmdline->string;

	cmdline->type = MULTIBOOT_TAG_TYPE_CMDLINE;
	cmdline->size = sizeof(*cmdline);

	/* Copy image URI to base memory buffer as start of command line */
	len = ( format_uri ( image->uri, buf, remaining ) + 1 /* NUL */ );
	if ( len > remaining )
		len = remaining;
	buf += len;
	remaining -= len;
	cmdline->size += len;

	/* Copy command line to base memory buffer, if present */
	if ( image->cmdline ) {
		buf--;
		cmdline->size--;
		remaining++;
		len = ( snprintf ( buf, remaining, " %s", image->cmdline ) + 1 /* NUL */ );
		if ( len > remaining )
			len = remaining;
	}

	DBGC ( image, "MULTIBOOT2 %p cmdline: %s\n", image, cmdline->string );

	cmdline->size += len;
	return cmdline->size;
}

/**
 * FIXME Load raw multiboot image into memory
 *
 * @v image		Multiboot file
 * @v hdr		Multiboot header descriptor
 * @ret entry		Entry point
 * @ret max		Maximum used address
 * @ret rc		Return status code
 */
static int multiboot2_load ( struct image *image, struct multiboot2_header_info *hdr,
			     struct multiboot2_tags *tags, physaddr_t *load,
			     physaddr_t *entry, physaddr_t *max ) {
	userptr_t buffer;
	size_t offset;
	size_t filesz;
	size_t memsz;
	size_t doffset;
	int rc;

	offset = ( hdr->offset - tags->addr.header_addr + tags->addr.load_addr );

	DBGC ( image, "MULTIBOOT2 offset %zx\n", offset );

	// FIXME: multiboot1 has "image->len - offset" ???
	filesz = ( tags->addr.load_end_addr ?
		   ( tags->addr.load_end_addr - tags->addr.load_addr ) :
		   image->len  );

	DBGC ( image, "MULTIBOOT2 filesz %zx\n", filesz );

	memsz = ( tags->addr.bss_end_addr ?
		  ( tags->addr.bss_end_addr - tags->addr.load_addr ) : filesz );

	DBGC ( image, "MULTIBOOT2 memsz %zx\n", memsz );

	DBGC ( image, "MULTIBOOT2 page-aligned base %x\n", tags->addr.load_addr & (~EFI_PAGE_MASK));

	doffset = tags->addr.load_addr & EFI_PAGE_MASK;

	buffer = phys_to_user ( tags->addr.load_addr & (~EFI_PAGE_MASK));

	// FIXME: is this right?
	memsz += doffset;

	// FIXME: do we even want to use this, it's an addition from mb2 patches
	// for EFI anyway
	if ( ( rc = prep_segment ( buffer, filesz, memsz ) ) != 0 ) {
		DBGC ( image, "MULTIBOOT2 %p could not prepare segment: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}

	/* Copy image to segment */
	memcpy_user ( buffer, doffset, image->data, offset, filesz );

	*load = tags->addr.load_addr;
	*max = ( tags->addr.load_addr + memsz );

	if (tags->entry_addr_efi64_valid) {
		*entry = tags->entry_addr_efi64;
	} else if (tags->entry_addr_efi32_valid) {
		*entry = tags->entry_addr_efi32;
	} else if (tags->entry_addr_valid) {
		*entry = tags->entry_addr;
	} else {
		printf("ERROR: no entry address\n");
		return -EINVAL;
	}

	return 0;
}

static size_t adjust_tag_offset(size_t offset) {
	if ((offset & 7) != 0) {
		return ((offset + 8) & ~7);
	}
	return offset;
}

/**
 * Add multiboot modules
 */
static size_t multiboot2_add_modules ( struct image *image, size_t offset ) {
	struct image *module_image;
	struct multiboot_tag_module *module;
	char *buf;
	size_t remaining;
	size_t len;

	/* Add each image as a multiboot module */
	for_each_image ( module_image ) {

		/* Do not include kernel image itself as a module */
		if ( module_image == image )
			continue;

		/*
		 * FIXME: loader allocates in chunks, then relocates after
		 * exiting boot services. ipxe has no support for this; we might
		 * well hit the issue where we can't actually allocate enough
		 * pages for our huge boot archive. This is system-dependent...
		 */

		/* Add module to list */
		module = (struct multiboot_tag_module *)&mb2_bib.bib[offset];
		module->type = MULTIBOOT_TAG_TYPE_MODULE;
		module->size = sizeof(*module);
		module->mod_start = user_to_phys ( module_image->data, 0 );
		module->mod_end = user_to_phys ( module_image->data, module_image->len );

		buf = module->cmdline;
		remaining = MB_MAX_BOOTINFO_SIZE - offset - sizeof(*module);

		/* Copy image URI to base memory buffer as start of command line */
		len = ( format_uri ( module_image->uri, buf, remaining ) + 1 /* NUL */ );
		if ( len > remaining )
			len = remaining;
		buf += len;
		remaining -= len;
		module->size += len;

		/* Copy command line to base memory buffer, if present */
		if ( module_image->cmdline ) {
			buf--;
			module->size--;
			remaining++;
			len = ( snprintf ( buf, remaining, " %s", module_image->cmdline ) + 1 /* NUL */ );
			if ( len > remaining )
				len = remaining;
			module->size += len;
		}

		offset += module->size;
		offset = adjust_tag_offset(offset);

		DBGC ( image, "MULTIBOOT2 %p module %s is [%x,%x): %s\n",
			   image, module_image->name, module->mod_start,
			   module->mod_end, module->cmdline );
	}

	return offset;
}

#ifdef EFIAPI

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
	UINTN size = sizeof (efi_mmap_buf);
	UINT32 descr_version;
	EFI_STATUS efirc;
	UINTN descr_size;
	UINTN key;

	efirc = bs->GetMemoryMap ( &size, (EFI_MEMORY_DESCRIPTOR *)efi_mmap_buf,
				   &key, &descr_size, &descr_version );

	if (efirc != 0) {
		printf ( "GetMemoryMap failed with %d\n", (int) efirc );
		return efirc;
	}

	mp->mmap_buf = efi_mmap_buf;
	mp->nr_descrs = size / descr_size;
	mp->descr_size = descr_size;
	mp->descr_version = descr_version;
	mp->key = key;
	return 0;
}

static multiboot_uint32_t
convert_efi_type(EFI_MEMORY_TYPE type)
{
	switch (type) {
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

	for (i = 0; i < em->nr_descrs; i++) {
		EFI_MEMORY_DESCRIPTOR *d = EM_ENTRY(em, i);
		multiboot_uint32_t mt = convert_efi_type(d->Type);
		struct multiboot_mmap_entry *me = &mmap[nr];

		DBGC ( image, "EM[%zd]: PhysicalStart 0x%llx "
		       "NumberOfPages %lld Type 0x%d\n", i, d->PhysicalStart,
		       d->NumberOfPages, d->Type );

		if (lastme != NULL && mt== lastme->type &&
			d->PhysicalStart == lastme->addr + lastme->len) {
			lastme->len += d->NumberOfPages << EFI_PAGE_SHIFT;
			continue;
		}

		if (bufsize < (nr + 1) * sizeof (*me)) {
			printf ( "not enough space for mmap (%lx < %lx)\n",
			    bufsize, (nr + 1) * sizeof(*me) );
			return -ENOMEM;
		}

		me->addr = d->PhysicalStart;
		me->len =  d->NumberOfPages << EFI_PAGE_SHIFT;
		me->type = mt;
		me->zero = 0;
		lastme = me;
		nr++;
	}

	return nr * sizeof (*mmap);
}

/**
 *
 * Supply both MMAP tag type contents.  They're duplicating information, but at
 * least Illumos doesn't parse MULTIBOOT_TAG_TYPE_EFI_MMAP, so we must supply
 * MULTIBOOT_TAG_TYPE_MMAP as well.
 */
static size_t multiboot2_add_mmap ( struct image *image, size_t offset ) {
	struct multiboot_tag_efi_mmap *emt = (void *)&mb2_bib.bib[offset];
	struct multiboot_tag_mmap *mt;
	struct efi_mmap em;
	EFI_STATUS efirc;
	ssize_t size;

	efirc = get_efi_mmap ( &em );

	if (efirc != 0) {
		// FIXME
		return 0;
        }

	size = em.nr_descrs * em.descr_size;

	emt->type = MULTIBOOT_TAG_TYPE_EFI_MMAP;
	emt->size = sizeof (*emt) + size;
	emt->descr_size = em.descr_size;
	emt->descr_vers = em.descr_version;

	offset += sizeof (*emt);

	memcpy_user ( (userptr_t)mb2_bib.bib, offset,
		      (userptr_t)em.mmap_buf, 0, size );

	offset += size;
	offset = adjust_tag_offset(offset);

	mt = (void *)&mb2_bib.bib[offset];
	mt->type = MULTIBOOT_TAG_TYPE_MMAP;
	mt->entry_size = sizeof(struct multiboot_mmap_entry);
	mt->entry_version = 0;

	offset += sizeof(*mt);

	size = multiboot2_build_mmap ( image, &em, (void *)&mb2_bib.bib[offset],
				       MB_MAX_BOOTINFO_SIZE - offset );

        if (size < 0) {
		// FIXME
		return 0;
	}

	mt->size = sizeof (*mt) + size;
	offset += size;

	return offset;
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
static void exit_boot_services ( struct image *image ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	struct efi_mmap em;
	EFI_STATUS efirc;
	int tries = 0;

again:
	efirc = get_efi_mmap ( &em );

	if (efirc != 0) {
		// FIXME
		return;
        }

	efirc = bs->ExitBootServices ( efi_image_handle, (UINTN) em.key );

	if (efirc == EFI_INVALID_PARAMETER && tries++ == 0)
		goto again;

	if (efirc != 0) {
		DBGC ( image, "ExitBootServices() failed with %d\n",
		       (int) efirc );
		//	while ( 1 ) {}
	}
}

#endif

/**
 * Prepare segment for loading
 *
 * @v segment		Segment start
 * @v filesz		Size of the "allocated bytes" portion of the segment
 * @v memsz		Size of the segment
 * @ret rc		Return status code
 */
void multiboot2_boot(uint32_t *bib, uint32_t entry) {
#ifdef EFIAPI
	__asm__ __volatile__ ( "push %%rbp\n\t"
						   "call *%%rdi\n\t"
						   "pop %%rbp\n\t"
					   : : "a" ( MULTIBOOT2_BOOTLOADER_MAGIC ),
						   "b" ( bib ),
						   "D" ( entry )
						 : "rcx", "rdx", "rsi", "memory" );
#else
	(void)bib;
	(void)entry;
#endif
}

/**
 * Execute multiboot2 image
 *
 * @v image		Multiboot image
 * @ret rc		Return status code
 */
static int multiboot2_exec ( struct image *image ) {
	struct multiboot2_header_info hdr;
	struct multiboot2_tags mb_tags;
	struct multiboot_tag *tag;
	struct multiboot_tag_load_base_addr *load_base_addr_tag;
#ifdef EFIAPI
	struct multiboot_tag_efi64 *tag_efi64;
#endif
	uint32_t *total_size;
	uint32_t *reserved;
	physaddr_t load = 0;
	physaddr_t entry = 0;
	physaddr_t max;
	size_t offset;
	int rc;

	/* Locate multiboot2 header, if present */
	if ( ( rc = multiboot2_find_header ( image, &hdr ) ) != 0 ) {
		DBGC ( image, "MULTIBOOT2 %p has no multiboot header\n",
			   image );
		return rc;
	}

	/* Abort if we detect tags that we cannot support */
	if ( ( rc = multiboot2_validate_tags ( image, &hdr, &mb_tags ) ) != 0 ) {
		DBGC ( image, "MULTIBOOT2 %p contains unsupported tags\n",
			   image );
		return -ENOTSUP;
	}

	/* Attempt to load the image into memory of our choosing */
	if ( ( rc = multiboot2_load ( image, &hdr, &mb_tags, &load, &entry, &max ) ) != 0) {
		DBGC ( image, "MULTIBOOT2 %p could not load\n", image );
		return rc;
	}

	/* Populate multiboot information structure */
	offset = 0;

	total_size = (uint32_t *)&mb2_bib.bib[offset];
	offset += sizeof(*total_size);

	reserved = (uint32_t *)&mb2_bib.bib[offset];
	offset += sizeof(*reserved);

	/* Clear out the reserved word */
	*reserved = 0;

	/* Add the load base address tag */
	load_base_addr_tag = (struct multiboot_tag_load_base_addr *)&mb2_bib.bib[offset];
	load_base_addr_tag->type = MULTIBOOT_TAG_TYPE_LOAD_BASE_ADDR;
	load_base_addr_tag->size = sizeof(*load_base_addr_tag);
	load_base_addr_tag->load_base_addr = load;
	offset += load_base_addr_tag->size;
	offset = adjust_tag_offset(offset);

#ifdef EFIAPI
	if (mb_tags.keep_boot_services) {
		/* Add the EFI boot services not terminated tag */
		tag = (struct multiboot_tag *)&mb2_bib.bib[offset];
		tag->type = MULTIBOOT_TAG_TYPE_EFI_BS;
		tag->size = sizeof(*tag);
		offset += tag->size;
		offset = adjust_tag_offset(offset);
	}

	/* Add the EFI 64-bit image handle pointer */
	tag_efi64 = (struct multiboot_tag_efi64 *)&mb2_bib.bib[offset];
	tag_efi64->type = MULTIBOOT_TAG_TYPE_EFI64_IH;
	tag_efi64->size = sizeof(*tag_efi64);
	tag_efi64->pointer = (multiboot_uint64_t)efi_image_handle;
	offset += tag_efi64->size;
	offset = adjust_tag_offset(offset);

	/* Add the EFI 64-bit system table handle pointer */
	tag_efi64 = (struct multiboot_tag_efi64 *)&mb2_bib.bib[offset];
	tag_efi64->type = MULTIBOOT_TAG_TYPE_EFI64;
	tag_efi64->size = sizeof(*tag_efi64);
	tag_efi64->pointer = (multiboot_uint64_t)efi_systab;
	offset += tag_efi64->size;
	offset = adjust_tag_offset(offset);

	// FIXME: = versus += really sucks
	offset = multiboot2_add_mmap ( image, offset );
	offset = adjust_tag_offset(offset);
#endif

	offset += multiboot2_add_cmdline ( image, offset );
	offset = adjust_tag_offset(offset);

	offset += multiboot2_add_bootloader ( image, offset );
	offset = adjust_tag_offset(offset);

	offset = multiboot2_add_modules ( image, offset );
	offset = adjust_tag_offset(offset);

	/* Terminate the tags */
	tag = (struct multiboot_tag *)&mb2_bib.bib[offset];
	tag->type = 0;
	tag->size = sizeof(*tag);
	offset += tag->size;

	*total_size = offset;

	DBGC ( image, "MULTIBOOT2 %p BIB is %d bytes\n", image, *total_size );
	DBGC ( image, "MULTIBOOT2 %p starting execution at %lx\n", image, entry );

#ifdef EFIAPI
	if ( !mb_tags.keep_boot_services ) {
		exit_boot_services ( image );
	} else {
		/*
		 * Multiboot images may not return and have no callback
		 * interface, so shut everything down prior to booting the OS.
		 */
		shutdown_boot();
	}
#endif

	/* Jump to OS with flat physical addressing */

	if ( mb_tags.entry_addr_efi64_valid ) {
		multiboot2_boot ( total_size, entry );
	} else {
		// FIXME: efi32 not supported

		extern void multiboot2_tramp(uint32_t, uint64_t, uint64_t);

		multiboot2_tramp ( MULTIBOOT2_BOOTLOADER_MAGIC, (uint64_t)total_size, entry );
	}

	DBGC ( image, "MULTIBOOT2 %p returned\n", image );

	/* It isn't safe to continue after calling shutdown() */
	while ( 1 ) {}

	return -ECANCELED;  /* -EIMPOSSIBLE, anyone? */
}

/**
 * Probe multiboot2 image
 *
 * @v image		Multiboot file
 * @ret rc		Return status code
 */
static int multiboot2_probe ( struct image *image ) {
	struct multiboot2_header_info hdr;
	int rc;

	/* Locate multiboot2 header, if present */
	if ( ( rc = multiboot2_find_header ( image, &hdr ) ) != 0 ) {
		DBGC ( image, "MULTIBOOT2 %p has no multiboot2 header\n",
			   image );
		return rc;
	}
	DBGC ( image, "MULTIBOOT2 %p found header at offset %zx with architecture %08x and header_length %d\n",
		   image, hdr.offset, hdr.mb.architecture, hdr.mb.header_length );
	return 0;
}

/** Multiboot image type */
struct image_type multiboot2_image_type __image_type ( PROBE_MULTIBOOT2 ) = {
	.name = "Multiboot 2",
	.probe = multiboot2_probe,
	.exec = multiboot2_exec,
};
