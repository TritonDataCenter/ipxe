/*
 * Copyright (C) 2016 Star Lab Corp.
 * Copyright 2020 Joyent, Inc.
 * Copyright 2024 MNX Cloud, Inc.
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
 * An illumos kernel is not an EFI image, and multiboot1 cannot load under
 * UEFI.  Thus, multiboot2 is the only hope we have when in UEFI. The format is
 * similar to that of multiboot1.
 *
 * This implementation is certainly incomplete - aside from the lack of legacy
 * BIOS support - but it's sufficient.
 */

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <strings.h>
#include <stdbool.h>

#include <ipxe/uaccess.h>
#include <ipxe/image.h>
#include <ipxe/segment.h>
#include <ipxe/io.h>
#include <ipxe/init.h>
#include <ipxe/features.h>
#include <ipxe/umalloc.h>
#include <ipxe/uri.h>
#include <ipxe/version.h>

#include <multiboot2.h>

FEATURE ( FEATURE_IMAGE, "MBOOT2", DHCP_EB_FEATURE_MULTIBOOT2, 1 );

#ifdef EFIAPI

#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/GraphicsOutput.h>

#define P2ROUNDUP(x, align) (-(-(x) & -(align)))

#define BIB_MAX_SIZE 4096
#define	BIB_ADDR(mb2) ((void *)&((mb2)->bib[(mb2)->bib_offset]))
#define BIB_REMAINING(mb2) (BIB_MAX_SIZE - (mb2)->bib_offset)

#define	MB2_STACK_OFF (EFI_PAGE_SIZE * 2)

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

	/* Kernel information. */
	struct mb2_entry kernel_entry;
	uint32_t kernel_load_addr;
	size_t kernel_file_offset;
	userptr_t kernel_image;
	size_t kernel_filesz;
	size_t kernel_memsz;

	union {
		uint64_t bib_align;
		char bib[BIB_MAX_SIZE];
	};

	size_t bib_offset;

	void *multiboot2_stack;
};

extern void multiboot2_bounce ( struct mb2 *, void *,
				void (*fp)( struct mb2 * ) );
extern void multiboot2_entry ( uint32_t, uint64_t, uint64_t );
static void multiboot2_enter_kernel ( struct mb2 * );

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

		size_t remaining = image->len - offset;

		/* Refill buffer if applicable */
		buf_idx = ( ( offset % sizeof ( buf ) ) / sizeof ( buf[0] ) );
		if ( buf_idx == 0 ) {
			bzero ( buf, sizeof ( buf ) );
			copy_from_user ( buf, image->data, offset,
				remaining > sizeof ( buf ) ?
				sizeof ( buf ) : remaining );
		}

		if ( buf[buf_idx] != MULTIBOOT2_HEADER_MAGIC )
			continue;

		if ( remaining < sizeof ( hdr->mb ) )
			return -ENOSPC;

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
		 * Note that we don't actually supply bootdev
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
		if ( rc )
			return rc;
		break;
	}

	case MULTIBOOT_HEADER_TAG_ADDRESS: {
		struct multiboot_header_tag_address load;

		if ( tag->size != sizeof ( load ) ) {
			printf ( "invalid address tag size %x\n", tag->size );
			return -EINVAL;
		}

		copy_from_user ( &load, mb2->image->data, offset, tag->size );

		DBGC ( mb2->image, "address tag: header_addr 0x%x, "
		       "load_addr 0x%x, load_end_addr 0x%x "
		       "bss_end_addr 0x%x\n", load.header_addr,
		       load.load_addr, load.load_end_addr, load.bss_end_addr );

		mb2->kernel_load_addr = load.load_addr;

		mb2->kernel_file_offset = ( mb2->image_hdr.file_offset -
			load.header_addr + mb2->kernel_load_addr );

		mb2->kernel_filesz = ( load.load_end_addr ?
		   ( load.load_end_addr - mb2->kernel_load_addr ) :
		   mb2->image->len - mb2->kernel_file_offset );

		mb2->kernel_memsz = ( load.bss_end_addr ?
		  ( load.bss_end_addr - mb2->kernel_load_addr ) :
		  mb2->kernel_filesz );

		mb2->kernel_image = mb2->image->data;
		break;
	}

	case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS:
		copy_from_user ( &entry_tag, mb2->image->data,
				 offset, tag->size );

		mb2->kernel_entry.type = ENTRY_I386;
		mb2->kernel_entry.addr = entry_tag.entry_addr;
		break;

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
		printf ( "Keeping boot services unsupported" );
		rc = -ENOTSUP;
		break;

	case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI32:
		printf ( "unsupported tag ENTRY_ADDRESS_EFI32" );
		rc = -ENOTSUP;
		break;

	case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI64:
		copy_from_user ( &entry_tag, mb2->image->data,
				 offset, tag->size );

		mb2->kernel_entry.type = ENTRY_EFI64;
		mb2->kernel_entry.addr = entry_tag.entry_addr;
		break;

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
				printf ( "%p missing address\n", mb2->image );
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

		if ( rc )
			return rc;

		offset += tag.size + (MULTIBOOT_TAG_ALIGN - 1);
		offset = offset & ~(MULTIBOOT_TAG_ALIGN - 1);
	}

	printf ( "%p missing end tag\n", mb2->image );
	return -ENOTSUP;
}

static int bib_get_space ( struct mb2 *mb2, size_t size ) {
	if ( BIB_REMAINING( mb2 ) < size ) {
		printf ( "%p exceeded BIB_MAX_SIZE ", mb2->image );
		return -ENOSPC;
	}

	mb2->bib_offset += size;
	return 0;
}

static void *bib_open_tag ( struct mb2 *mb2, multiboot_uint32_t type,
			    size_t size ) {
	struct multiboot_tag *tag;

	if ( ( mb2->bib_offset & 7 ) != 0 ) {
		size_t aligned_off = ( ( mb2->bib_offset + 8 ) & ~7 );
		if ( aligned_off > BIB_MAX_SIZE )
			return NULL;
		mb2->bib_offset = aligned_off;
	}

	DBGC ( mb2->image, "MULTIBOOT2 tag %d at 0x%zx\n", type,
	       mb2->bib_offset );

	tag = BIB_ADDR ( mb2 );

	if ( bib_get_space ( mb2, size ) )
		return NULL;

	tag->type = type;
	return tag;
}

static void bib_close_tag ( struct mb2 *mb2, void *tagp ) {
	struct multiboot_tag *tag = tagp;
	tag->size = (char *)BIB_ADDR ( mb2 ) - (char *)tagp;
}

/*
 * An image cmdline buffer is the URI of the image appended with its cmdline.
 */
static int multiboot2_fmt_cmdline ( struct mb2 *mb2, struct image *image,
				    char *buf ) {
	size_t remaining = BIB_REMAINING ( mb2 );
	size_t len;

	len = format_uri ( image->uri, buf, remaining ) + 1;
	if ( len > remaining )
		return -ENOSPC;

	if ( image->cmdline == NULL ) {
		mb2->bib_offset += len;
		return 0;
	}

	/* Overwrite the NIL. */
	len--;

	mb2->bib_offset += len;
	buf += len;
	remaining -= len;

	len = snprintf ( buf, remaining, " %s", image->cmdline ) + 1;
	if ( len > remaining )
		return -ENOSPC;

	mb2->bib_offset += len;
	return 0;
}

static int multiboot2_add_cmdline ( struct mb2 *mb2 ) {
	struct multiboot_tag_string *tag;
	int rc;

	if ( ( tag = bib_open_tag ( mb2, MULTIBOOT_TAG_TYPE_CMDLINE,
	       sizeof ( *tag ) ) ) == NULL )
		return -ENOSPC;

	rc = multiboot2_fmt_cmdline ( mb2, mb2->image, tag->string );

	if ( rc )
		return rc;

	bib_close_tag ( mb2, tag );
	return 0;
}

static int multiboot2_add_bootloader ( struct mb2 *mb2 ) {
	struct multiboot_tag_string *tag;
	size_t len;

	if ( ( tag = bib_open_tag ( mb2, MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME,
	       sizeof ( *tag ) ) ) == NULL )
		return -ENOSPC;

	len = snprintf ( tag->string, BIB_REMAINING ( mb2 ), "iPXE %s",
			 product_version ) + 1;

	if (len > BIB_REMAINING ( mb2 ))
		return -ENOSPC;

	mb2->bib_offset += len;
	bib_close_tag ( mb2, tag );
	return 0;
}

static EFI_STATUS multiboot2_fb_colour_mask ( uint32_t mask, uint8_t *scale,
					uint8_t *lsb ) {
	uint32_t check;

	/* Fill in LSB and scale */
	*lsb = ( mask ? ( ffs ( mask ) - 1 ) : 0 );
	*scale = fls ( mask >> *lsb );

	/* Check that original mask was contiguous */
	check = ( ( 0xff >> ( 8 - *scale ) ) << *lsb );
	if ( check != mask )
		return EFI_UNSUPPORTED;

	return EFI_SUCCESS;
}

/*
 * See https://bsdio.com/edk2/docs/master/_console_out_device_8h.html
 */
#if !defined(EFI_CONSOLE_OUT_DEVICE_GUID)
#define	EFI_CONSOLE_OUT_DEVICE_GUID	\
{ 0xd3b36f2c, 0xd551, 0x11d4, {0x9a, 0x46, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d } }
#endif

static int multiboot2_build_framebuffer (
		struct multiboot_tag_framebuffer *tag ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_HANDLE *handles, gop_handle;
	UINTN count, i;
	EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
	EFI_STATUS status;
	EFI_GUID gEfiConsoleOutDeviceGuid = EFI_CONSOLE_OUT_DEVICE_GUID;

	/* Get all GOP handles */
	status = bs->LocateHandleBuffer ( ByProtocol,
		&efi_graphics_output_protocol_guid, NULL, &count, &handles );
	if (status != EFI_SUCCESS)
		return -ENOTSUP;

	/*
	 * Search for ConOut protocol, if not found, use first handle.
	 * See illumos issue "13453 loader.efi: handle multiple gop instances"
	 */
	gop_handle = NULL;
	gop = NULL;
	for (i = 0; i < count; i++) {
		EFI_GRAPHICS_OUTPUT_PROTOCOL *tgop;
		void *dummy;

		status = bs->OpenProtocol ( handles[i],
			&efi_graphics_output_protocol_guid,
			(void **)&tgop, efi_image_handle, handles[i],
			EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
		if (status != EFI_SUCCESS)
			continue;

		if (tgop->Mode->Info->PixelFormat == PixelBltOnly ||
		    tgop->Mode->Info->PixelFormat >= PixelFormatMax)
			continue;

		status = bs->OpenProtocol ( handles[i],
			&gEfiConsoleOutDeviceGuid,
			&dummy, efi_image_handle, handles[i],
			EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
		if (status == EFI_SUCCESS) {
			gop_handle = handles[i];
			gop = tgop;
			break;
		} else if (gop_handle == NULL) {
			gop_handle = handles[i];
			gop = tgop;
		}
	}

	bs->FreePool ( handles );
	if (gop == NULL || gop->Mode->FrameBufferBase == 0)
		return -ENOTSUP;

	tag->common.type = MULTIBOOT_TAG_TYPE_FRAMEBUFFER;
	tag->common.size = sizeof (*tag);
	tag->common.framebuffer_addr = gop->Mode->FrameBufferBase;
	tag->common.framebuffer_width = gop->Mode->Info->HorizontalResolution;
	tag->common.framebuffer_height = gop->Mode->Info->VerticalResolution;
	/*
	 * UEFI pixels are using 32-bits, so we do use literal constants
	 * 32 and 4.
	 */
	tag->common.framebuffer_bpp = 32;
	tag->common.framebuffer_pitch = gop->Mode->Info->PixelsPerScanLine * 4;
	tag->common.framebuffer_type = MULTIBOOT_FRAMEBUFFER_TYPE_RGB;
	tag->common.reserved = 0;

	switch (gop->Mode->Info->PixelFormat) {
	case PixelRedGreenBlueReserved8BitPerColor:
	case PixelBltOnly:
		status = multiboot2_fb_colour_mask(0x000000ff,
			&tag->framebuffer_red_mask_size,
			&tag->framebuffer_red_field_position);
		if (status != EFI_SUCCESS)
			return -ENOTSUP;
		status = multiboot2_fb_colour_mask(0x0000ff00,
			&tag->framebuffer_green_mask_size,
			&tag->framebuffer_green_field_position);
		if (status != EFI_SUCCESS)
			return -ENOTSUP;
		status = multiboot2_fb_colour_mask(0x00ff0000,
			&tag->framebuffer_blue_mask_size,
			&tag->framebuffer_blue_field_position);
		if (status != EFI_SUCCESS)
			return -ENOTSUP;
		break;
	case PixelBlueGreenRedReserved8BitPerColor:
		status = multiboot2_fb_colour_mask(0x00ff0000,
			&tag->framebuffer_red_mask_size,
			&tag->framebuffer_red_field_position);
		if (status != EFI_SUCCESS)
			return -ENOTSUP;
		status = multiboot2_fb_colour_mask(0x0000ff00,
			&tag->framebuffer_green_mask_size,
			&tag->framebuffer_green_field_position);
		if (status != EFI_SUCCESS)
			return -ENOTSUP;
		status = multiboot2_fb_colour_mask(0x000000ff,
			&tag->framebuffer_blue_mask_size,
			&tag->framebuffer_blue_field_position);
		if (status != EFI_SUCCESS)
			return -ENOTSUP;
		break;
	case PixelBitMask:
		status = multiboot2_fb_colour_mask(
			gop->Mode->Info->PixelInformation.RedMask,
			&tag->framebuffer_red_mask_size,
			&tag->framebuffer_red_field_position);
		if (status != EFI_SUCCESS)
			return -ENOTSUP;
		status = multiboot2_fb_colour_mask(
			gop->Mode->Info->PixelInformation.GreenMask,
			&tag->framebuffer_green_mask_size,
			&tag->framebuffer_green_field_position);
		if (status != EFI_SUCCESS)
			return -ENOTSUP;
		status = multiboot2_fb_colour_mask(
			gop->Mode->Info->PixelInformation.BlueMask,
			&tag->framebuffer_blue_mask_size,
			&tag->framebuffer_blue_field_position);
		if (status != EFI_SUCCESS)
			return -ENOTSUP;
		break;
	default:
		return -ENOTSUP;
	}

	return 0;
}

static int multiboot2_add_framebuffer ( struct mb2 *mb2 ) {
	struct multiboot_tag_framebuffer *tag;

	if ( ( tag = bib_open_tag ( mb2, MULTIBOOT_TAG_TYPE_FRAMEBUFFER,
	       sizeof ( *tag ) ) ) == NULL )
		return -ENOSPC;

	/* Do not error out from failure to detect FB config */
	if (multiboot2_build_framebuffer( tag ) == 0)
		bib_close_tag ( mb2, tag );
	else
		mb2->bib_offset -= sizeof ( *tag );
	return 0;
}

static int multiboot2_add_modules ( struct mb2 * mb2 ) {
	struct image *module_image;

	/* Add each image as a multiboot module */
	for_each_image ( module_image ) {
		struct multiboot_tag_module *tag;
		int rc;

		/* Do not include kernel image itself as a module */
		if ( module_image == mb2->image )
			continue;

		if ( ( tag = bib_open_tag ( mb2, MULTIBOOT_TAG_TYPE_MODULE,
		       sizeof ( *tag ) ) ) == NULL )
			return -ENOSPC;

		tag->mod_start = user_to_phys ( module_image->data, 0 );
		tag->mod_end = user_to_phys ( module_image->data,
					      module_image->len );

		rc = multiboot2_fmt_cmdline ( mb2, module_image, tag->cmdline );

		if ( rc )
			return rc;

		bib_close_tag ( mb2, tag );

		DBGC ( mb2->image, "MULTIBOOT2 %p module %s is [%x,%x): %s\n",
		       mb2->image, module_image->name, tag->mod_start,
		       tag->mod_end, tag->cmdline );
	}

	return 0;
}

#define EM_ENTRY(em, i) ((EFI_MEMORY_DESCRIPTOR *)	\
	((em)->mmap_buf + (i) * ((em)->descr_size)))

static char *efi_mmap_buf;
static size_t efi_mmap_bufsize;

struct efi_mmap {
	char *mmap_buf;
	size_t nr_descrs;
	size_t descr_size;
	size_t descr_version;
	UINTN key;
};

static EFI_STATUS get_efi_mmap ( struct efi_mmap *mp ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	UINTN size = efi_mmap_bufsize;
	UINT32 descr_version;
	EFI_STATUS efirc;
	UINTN descr_size;
	UINTN key;

again:
	efirc = bs->GetMemoryMap ( &size, (EFI_MEMORY_DESCRIPTOR *)efi_mmap_buf,
				   &key, &descr_size, &descr_version );

	if ( efirc ) {
		if ( efirc == EFI_BUFFER_TOO_SMALL ) {
			free ( efi_mmap_buf );

			if ( ( efi_mmap_buf = malloc ( size ) ) == NULL ) {
				printf ( "Failed to alloc %llx bytes for "
					"EFI memory map buffer\n", size );
				return EFI_BUFFER_TOO_SMALL;
			}

			goto again;
		}

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
 * type. We explicitly mark things such as EfiBootServicesCode as available,
 * because they will be, post-ExitBootServices().
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

		DBGC ( image, "EM[%zd]: 0x%llx-0x%llx Type 0x%d\n", i,
			d->PhysicalStart,
			d->PhysicalStart + EFI_PAGE_SIZE * d->NumberOfPages,
			d->Type );

		if ( lastme != NULL && mt == lastme->type &&
			d->PhysicalStart == lastme->addr + lastme->len ) {
			lastme->len += d->NumberOfPages << EFI_PAGE_SHIFT;
			continue;
		}

		if ( bufsize < ( ++nr ) * sizeof ( *me ) ) {
			printf ( "not enough space for mmap (%lx < %lx)\n",
			    bufsize, nr * sizeof ( *me ) );
			return -ENOSPC;
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
 * Supply the MMAP tag. This is built from the EFI mmap, but we don't supply
 * MULTIBOOT_TAG_TYPE_EFI_MMAP as well - illumos doesn't use it, and it can be
 * significantly larger than the space we have available (e.g. 250 entries on
 * one machine).
 */
static int multiboot2_add_mmap ( struct mb2 *mb2 ) {
	struct multiboot_tag_mmap *tag;
	struct efi_mmap em;
	EFI_STATUS efirc;
	ssize_t size;

	if ( ( efirc = get_efi_mmap ( &em ) ) != 0 )
		return -EEFI ( efirc );

	if ( ( tag = bib_open_tag ( mb2, MULTIBOOT_TAG_TYPE_MMAP,
	       sizeof ( *tag ) ) ) == NULL )
		return -ENOSPC;

	tag->entry_size = sizeof ( struct multiboot_mmap_entry );
	tag->entry_version = 0;

	size = multiboot2_build_mmap ( mb2->image, &em, BIB_ADDR ( mb2 ),
				       BIB_REMAINING ( mb2 ) );

        if ( size < 0 )
		return (int)size;

	(void) bib_get_space ( mb2, size );

	bib_close_tag ( mb2, tag );
	return 0;
}

static bool overlaps ( size_t s1, size_t e1, size_t s2, size_t e2 ) {
	return s1 < e2 && e1 >= s2;
}

/*
 * We've been requested to map the kernel at a certain fixed address.  If we
 * find that something will still be in use after exiting boot services, then
 * there's nothing we can do.
 */
static int multiboot2_check_mmap ( struct mb2 *mb2 ) {
	size_t kern_start = mb2->kernel_load_addr;
	size_t kern_end = mb2->kernel_load_addr + mb2->kernel_memsz;
	struct efi_mmap em;
	EFI_STATUS efirc;
	size_t i;

	if ( ( efirc = get_efi_mmap ( &em ) ) != 0 )
		return -EEFI ( efirc );

	for ( i = 0; i < em.nr_descrs; i++ ) {
		EFI_MEMORY_DESCRIPTOR *d = EM_ENTRY ( &em, i );
		multiboot_uint32_t mt = convert_efi_type ( d->Type );
		size_t mm_start = d->PhysicalStart;
		size_t mm_end = d->PhysicalStart +
				  ( d->NumberOfPages * EFI_PAGE_SIZE );

		if ( mt == MULTIBOOT_MEMORY_AVAILABLE )
			continue;

		if ( ! ( overlaps ( kern_start, kern_end, mm_start, mm_end ) ) )
			continue;

		printf ( "EFI map entry 0x%zx-0x%zx (type %d) overlaps "
			 "kernel map 0x%zx-0x%zx\n", mm_start, mm_end, d->Type,
			 kern_start, kern_end );
		return -ENOSPC;
	}


	/*
	 * These are (hopefully) less likely, but paranoia here is a good idea.
	 * If we do hit any of these, we'll have to implement more relocation
	 * code (and somehow make sure that our code copies only have
	 * %rip-relative relocations).
	 */

	if ( overlaps ( kern_start, kern_end, mb2->kernel_image,
			mb2->kernel_image + mb2->kernel_memsz ) ) {
		printf ( "Kernel image 0x%zx-0x%zx overlaps "
			 "kernel map 0x%zx-0x%zx\n", mb2->kernel_image,
			 mb2->kernel_image + mb2->kernel_memsz,
			 kern_start, kern_end );
		return -ENOSPC;
	}

	if ( overlaps ( kern_start, kern_end, (intptr_t)multiboot2_entry,
			(intptr_t)multiboot2_entry + EFI_PAGE_SIZE ) ) {
		printf ( "multiboot2_entry 0x%p overlaps "
			 "kernel map 0x%zx-0x%zx\n", multiboot2_entry,
			 kern_start, kern_end );
		return -ENOSPC;
	}

	if ( overlaps ( kern_start, kern_end, (intptr_t)multiboot2_enter_kernel,
			(intptr_t)multiboot2_enter_kernel + EFI_PAGE_SIZE ) ) {
		printf ( "multiboot2_enter_kernel 0x%p overlaps "
			 "kernel map 0x%zx-0x%zx\n", multiboot2_enter_kernel,
			 kern_start, kern_end );
		return -ENOSPC;
	}

	return 0;
}

/*
 * We just need a small unused region that we're definitely not going to copy
 * the kernel over during the bounce to kernel. Unfortunately, on some Dell
 * systems, boot services allocate all of the region below the kernel. In this
 * case, we'll try a less bounded allocation, in the hope that we're not going
 * to later clash with our kernel load area. If we do, we'll error out shortly.
 */
static struct mb2 *multiboot2_alloc_bounce_buffer ( struct mb2 *mb2 ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_PHYSICAL_ADDRESS phys_addr = P2ROUNDUP ( mb2->kernel_load_addr,
						     EFI_PAGE_SIZE );
	size_t size = EFI_PAGE_SIZE * 3;
	int efirc;
	char *p;

	if ( ( efirc = bs->AllocatePages ( AllocateMaxAddress,
		EfiLoaderData, EFI_SIZE_TO_PAGES ( size ),
		&phys_addr ) ) != 0 ) {
			/* See efi_urealloc() hack. */
			phys_addr = 0x40000000UL;
		if ( ( efirc = bs->AllocatePages ( AllocateMaxAddress,
			EfiLoaderData, EFI_SIZE_TO_PAGES ( size ),
			&phys_addr ) ) != 0 ) {
			printf ( "MULTIBOOT2 could not allocate bounce "
			         "buffer: %s\n", strerror ( -EEFI ( efirc ) ) );
			return NULL;
		}
	}

	DBGC ( mb2->image, "MULTIBOOT2 bounce is at %llx\n", phys_addr);

	memset ( (void *) phys_to_user ( phys_addr ), 0, size );
	memcpy_user ( phys_to_user ( phys_addr), 0,
		      (userptr_t)mb2, 0, sizeof ( *mb2 ) );

	p = (char *)phys_to_user ( phys_addr );
	mb2 = (struct mb2 *)p;
	assert ( sizeof ( *mb2 ) < MB2_STACK_OFF );
	mb2->multiboot2_stack = p + MB2_STACK_OFF;
	return mb2;
}

/*
 * To successfully exit boot services, we must pass a non-stale mmap key.
 * However, the first time we call ->ExitBootServices(), this can trigger
 * EVT_SIGNAL_EXIT_BOOT_SERVICES handlers, which themselves can do allocations
 * and hence make the key stale.
 *
 * A second call will not trigger such handlers again, so trying twice should be
 * sufficient.
 *
 * The key is also why we need to re-get the mmap immediately before
 * ->ExitBootServices().
 */
static int exit_boot_services ( struct mb2 *mb2 ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	struct efi_mmap em;
	EFI_STATUS efirc;
	int tries = 0;

	DBGC ( mb2->image, "MULTIBOOT2 exit_boot_services ( )\n");

again:
	if ( ( efirc = get_efi_mmap ( &em ) ) != 0 )
		return -EEFI ( efirc );

	efirc = bs->ExitBootServices ( efi_image_handle, (UINTN)em.key );

	if ( efirc == EFI_INVALID_PARAMETER && tries++ == 0 )
		goto again;

	if ( efirc ) {
		DBGC ( mb2->image, "ExitBootServices() failed with %d\n",
		       (int)efirc );
		return -EEFI ( efirc );
	}

	return 0;
}

/*
 * We need to copy the kernel image into the requested load address.  We've
 * already exited boot services, so we know we're OK to use that region if
 * it was previously EfiBootServicesCode/Data. We've also checked that the
 * region doesn't overlap with:
 *
 * - any runtime services code or data, unusable memory and the like
 * - multiboot2_enter_kernel
 * - multiboot2_entry
 * - mb2->kernel_image
 *
 * Our stack, and "mb2" itself, come from our bounce buffer. Thus, we shouldn't
 * be using anything that the relocation code below could over-write.
 */
static void multiboot2_enter_kernel ( struct mb2 *mb2 ) {
	char *load_addr = (char *)(intptr_t) mb2->kernel_load_addr;
	size_t i;

	/*
	 * A lame byte-by-byte implementation, but iPXE's memcpy() does this
	 * anyway...
	 */
	for ( i = 0; i < mb2->kernel_filesz; i++ ) {
		load_addr[i] = ( (char *)mb2->kernel_image )
			[mb2->kernel_file_offset + i];
	}

	for ( i = 0; i < mb2->kernel_memsz - mb2->kernel_filesz; i++ ) {
		load_addr[mb2->kernel_filesz + i] = '\0';
	}

	if ( mb2->kernel_entry.type == ENTRY_EFI64 ) {
		__asm__ __volatile__ ( "push %%rbp\n\t"
				       "call *%%rdi\n\t"
				       "pop %%rbp\n\t" : :
				       "a" ( MULTIBOOT2_BOOTLOADER_MAGIC ),
	                               "b" ( (uint32_t *)mb2->bib ),
				       "D" ( (uint32_t)mb2->kernel_entry.addr )
				       : "rcx", "rdx", "rsi", "memory" );
	} else {
		multiboot2_entry ( MULTIBOOT2_BOOTLOADER_MAGIC,
				   (uint64_t)mb2->bib, mb2->kernel_entry.addr );
	}

	printf ( "MULTIBOOT2 entry returned !\n" );

	for ( ;; ) {
	}
}

struct mb2 init_mb2 = { 0 };

static int multiboot2_exec ( struct image *image ) {
	struct mb2 *mb2 = &init_mb2;
	struct multiboot_tag_load_base_addr *load_tag;
	struct multiboot_tag_efi64_ih *efi64_ih_tag;
	struct multiboot_tag_efi64 *efi64_tag;
	struct multiboot_tag *tag;
	uint32_t *total_sizep;
	int rc;

	mb2->image = image;

	if ( ( rc = multiboot2_find_header ( mb2->image,
					     &mb2->image_hdr ) ) != 0 ) {
		DBGC ( image, "MULTIBOOT2 %p has no multiboot header\n",
		       image );
		return rc;
	}

	if ( ( rc = multiboot2_process_tags ( mb2 ) ) != 0 )
		return rc;

	if ( ( rc = multiboot2_check_mmap ( mb2 ) ) != 0 )
		return rc;

	if ( ( mb2 = multiboot2_alloc_bounce_buffer ( mb2 ) ) == NULL )
		return -ENOMEM;

	DBGC ( image, "MULTIBOOT2 multiboot2_enter_kernel is at %p\n",
		multiboot2_enter_kernel);
	DBGC ( image, "MULTIBOOT2 multiboot2_bounce is at %p\n",
	       multiboot2_bounce);
	DBGC ( image, "MULTIBOOT2 kernel at 0x%x-0x%zx\n",
	       mb2->kernel_load_addr,
	       mb2->kernel_load_addr + mb2->kernel_filesz);

	total_sizep = BIB_ADDR ( mb2 );
	mb2->bib_offset += sizeof ( *total_sizep );

	/* reserved field */
	mb2->bib_offset += sizeof ( uint32_t );

	if ( ( load_tag = bib_open_tag ( mb2,
	       MULTIBOOT_TAG_TYPE_LOAD_BASE_ADDR,
	       sizeof ( *load_tag ) ) ) == NULL )
		return -ENOSPC;
	load_tag->load_base_addr = mb2->kernel_load_addr;
	bib_close_tag ( mb2, load_tag );

	if ( ( efi64_ih_tag = bib_open_tag ( mb2, MULTIBOOT_TAG_TYPE_EFI64_IH,
	       sizeof ( *efi64_ih_tag ) ) ) == NULL )
		return -ENOSPC;
	efi64_ih_tag->pointer = (multiboot_uint64_t)efi_image_handle;
	bib_close_tag ( mb2, efi64_ih_tag );

	if ( ( efi64_tag = bib_open_tag ( mb2, MULTIBOOT_TAG_TYPE_EFI64,
	       sizeof ( *efi64_tag ) ) ) == NULL )
		return -ENOSPC;
	efi64_tag->pointer = (multiboot_uint64_t)efi_systab;
	bib_close_tag ( mb2, efi64_tag );

	if ( ( rc = multiboot2_add_mmap ( mb2 ) ) != 0 )
		return rc;

	if ( ( rc = multiboot2_add_cmdline ( mb2 ) ) != 0 )
		return rc;

	if ( ( rc = multiboot2_add_bootloader ( mb2 ) ) != 0 )
		return rc;

	if ( ( rc = multiboot2_add_framebuffer ( mb2 ) ) != 0 )
		return rc;

	if ( ( rc = multiboot2_add_modules ( mb2 ) ) != 0 )
		return rc;

	if ( ( tag = bib_open_tag ( mb2, MULTIBOOT_TAG_TYPE_END,
	       sizeof ( *tag ) ) ) == NULL )
		return -ENOSPC;
	bib_close_tag ( mb2, tag );

	*total_sizep = mb2->bib_offset;

	DBGC ( image, "MULTIBOOT2 %p BIB is %d bytes\n", image, *total_sizep );
	DBGC ( image, "MULTIBOOT2 %p starting execution at %x\n",
	       image, mb2->kernel_entry.addr );

	if ( ( rc = exit_boot_services ( mb2 ) ) != 0 )
		return rc;

	/*
	 * We have to bounce out and back again: GCC inline asm can't clobber
	 * the stack pointer.
	 */
	multiboot2_bounce ( mb2, mb2->multiboot2_stack,
			    multiboot2_enter_kernel );

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

static int multiboot2_exec ( struct image *image __unused ) {
	return -ENOTSUP;
}

static int multiboot2_probe ( struct image *image __unused ) {
	return -ENOEXEC;
}

#endif

/** Multiboot image type */
struct image_type multiboot2_image_type __image_type ( PROBE_MULTIBOOT2 ) = {
	.name = "Multiboot 2",
	.probe = multiboot2_probe,
	.exec = multiboot2_exec,
};
