// SPDX-License-Identifier: GPL-2.0-only
/*
 * kexec.c - kexec_load system call
 * Copyright (C) 2002-2004 Eric Biederman  <ebiederm@xmission.com>
 */


#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/security.h>
#include <linux/kexec.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/efi.h>
#include <linux/io.h>
#include <linux/mman.h>
#include <linux/fb.h>
#include <asm/desc.h>
#include "kexec_internal.h"

#include <asm/e820/api.h>
/* #include <uapi/asm/e820.h> */

static int copy_user_segment_list(struct kimage *image,
				  unsigned long nr_segments,
				  struct kexec_segment __user *segments)
{
	int ret;
	size_t segment_bytes;

	/* Read in the segments */
	image->nr_segments = nr_segments;
	segment_bytes = nr_segments * sizeof(*segments);
	ret = copy_from_user(image->segment, segments, segment_bytes);
	if (ret)
		ret = -EFAULT;

	return ret;
}

static int kimage_alloc_init(struct kimage **rimage, unsigned long entry,
			     unsigned long nr_segments,
			     struct kexec_segment __user *segments,
			     unsigned long flags)
{
	int ret;
	struct kimage *image;
	bool kexec_on_panic = flags & KEXEC_ON_CRASH;

	if (kexec_on_panic) {
		/* Verify we have a valid entry point */
		if ((entry < phys_to_boot_phys(crashk_res.start)) ||
		    (entry > phys_to_boot_phys(crashk_res.end)))
			return -EADDRNOTAVAIL;
	}

	/* Allocate and initialize a controlling structure */
	image = do_kimage_alloc_init();
	if (!image)
		return -ENOMEM;

	image->start = entry;

	ret = copy_user_segment_list(image, nr_segments, segments);
	if (ret)
		goto out_free_image;

	if (kexec_on_panic) {
		/* Enable special crash kernel control page alloc policy. */
		image->control_page = crashk_res.start;
		image->type = KEXEC_TYPE_CRASH;
	}

	ret = sanity_check_segment_list(image);
	if (ret)
		goto out_free_image;

	/*
	 * Find a location for the control code buffer, and add it
	 * the vector of segments so that it's pages will also be
	 * counted as destination pages.
	 */
	ret = -ENOMEM;
	image->control_code_page = kimage_alloc_control_pages(image,
					   get_order(KEXEC_CONTROL_PAGE_SIZE));
	if (!image->control_code_page) {
		pr_err("Could not allocate control_code_buffer\n");
		goto out_free_image;
	}

	if (!kexec_on_panic) {
		image->swap_page = kimage_alloc_control_pages(image, 0);
		if (!image->swap_page) {
			pr_err("Could not allocate swap buffer\n");
			goto out_free_control_pages;
		}
	}

	*rimage = image;
	return 0;
out_free_control_pages:
	kimage_free_page_list(&image->control_pages);
out_free_image:
	kfree(image);
	return ret;
}

/* #define DebugMSG( fmt, ... ) \ */
/* do { \ */
/*         printk( KERN_ERR "### %s:%d; " fmt "\n", __FUNCTION__, __LINE__, ## __VA_ARGS__ ); \ */
/* }  while (0) */

#define InternalSerialPuts( const_str )   \
do {                                      \
        char *str = const_str;            \
        while( *str != 0 )                \
                outb((int)*str++, 0x3f8); \
} while(0)

static char DebugMSG_buffer[1024];
#define DebugMSG( fmt, ... ) \
do { \
        sprintf( DebugMSG_buffer, "### %s:%d; " fmt "\n",  \
                 __FUNCTION__, __LINE__, ## __VA_ARGS__ ); \
        InternalSerialPuts( DebugMSG_buffer );             \
}  while (0)


/* Debug function to print contents of buffers */
void DumpBuffer( char* title, uint8_t *buff, unsigned long size )
{
        unsigned long i              = 0;
        char          *currentOutput = DebugMSG_buffer;

        printk( KERN_ERR "%s (%ld bytes @ 0x%px)\n", title, size, buff );

        currentOutput += sprintf( currentOutput, "%px: ", &buff[0] );
        for( i = 0; i < size; i++ ) {
                currentOutput += sprintf( currentOutput, "%02X ", buff[i] );
                if( (i+1) % 8 == 0 ) {
                        printk( KERN_ERR  "%s\n", DebugMSG_buffer);
                        currentOutput = DebugMSG_buffer;
                        *currentOutput = '\0';

                        if( i+1 < size )
                                currentOutput += sprintf( currentOutput, "%px: ", &buff[i+1] );
                }
        }

        if( i % 8 != 0 )
                printk( KERN_ERR  "%s\n", DebugMSG_buffer);

        printk( KERN_ERR  "\n");
}

/* This implementationis based on kimage_load_normal_segment */
static int kimage_load_pe_segment(struct kimage *image,
			          struct kexec_segment *segment)
{
	unsigned long   maddr;
	size_t          ubytes, mbytes;
	int             result;
	unsigned char   __user *buf              = NULL;
        void*           raw_image_offset         = NULL;
        unsigned long   offset_relative_to_image = 0;

	result  = 0;
	buf     = segment->buf;
	ubytes  = segment->bufsz;
	mbytes  = segment->memsz;

        /* Address of segment in efi image (ass seen in objdump*/
	maddr   = segment->mem;

        offset_relative_to_image  = maddr - image->raw_image_mem_base;
        raw_image_offset          = ( void* )image->raw_image + offset_relative_to_image;
        DebugMSG( "ubytes = 0x%lx; mbytes = 0x%lx; maddr = 0x%lx; "
                  "offset_relative_to_image = 0x%lx; raw_image_offset = %px",
                  ubytes, mbytes, maddr, offset_relative_to_image, raw_image_offset );
        DumpBuffer( "Segment start", buf, 32 );

	while (mbytes) {
		size_t uchunk, mchunk;

		mchunk = min_t(size_t, mbytes,
				PAGE_SIZE - (maddr & ~PAGE_MASK));
		uchunk = min(ubytes, mchunk);

                result = copy_from_user(raw_image_offset, buf, uchunk);
                DebugMSG( "copied 0x%lx bytes into raw image at 0x%px)",
                          uchunk, raw_image_offset );
	        raw_image_offset += uchunk;

                if (result)
                        return -EFAULT;

		ubytes -= uchunk;
		maddr  += mchunk;
		buf    += mchunk;
		mbytes -= mchunk;
	}

	return result;
}

/* Types for parsing .reloc relocation table in a PE. See
 * https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only
 */
typedef struct {
        uint32_t va_offset;  /* "Page RVA" */
        uint32_t total_size; /* Including this header. See "Block Size" */
} relocation_chunk_header_t;

typedef struct {
        uint16_t offset  : 12;
        uint16_t type    : 4;
} relocation_entry_t;


/* This is the offset added by u-root pekexec */
#define SEGMENTS_OFFSET_FROM_ZERO 0x1000000

/* This is the IMAGE_BASE from the PE */
/* TODO: Figure out this value programatically */
#define IMAGE_BASE                0x10000000

/* See
 * https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#base-relocation-types
 */
#define IMAGE_REL_BASED_DIR64     10

void parse_chunk_relocations( relocation_chunk_header_t* chunk, struct kimage* image )
{
        relocation_entry_t *relocs =
                  (void*)chunk + sizeof( relocation_chunk_header_t );

        uint32_t           num_relocs =
                  ( chunk->total_size - sizeof( relocation_chunk_header_t ) )
                  / sizeof( relocation_entry_t );

        unsigned long      absolute_image_start =
                        image->start - SEGMENTS_OFFSET_FROM_ZERO;

        unsigned long      raw_image_vs_PE_bias =
                        (unsigned long)image->raw_image_start -
                        absolute_image_start;

        int i;

        DebugMSG( "image->raw_image_start = 0x%lx; "
                  "image->start = 0x%lx; raw_image_vs_PE_bias = 0x%lx",
                  (unsigned long)image->raw_image_start, image->start,
                  raw_image_vs_PE_bias );

        for( i = 0; i < num_relocs; i++ ) {
                unsigned long address_in_image  =
                         relocs[i].offset + chunk->va_offset;
                uint64_t*     raw_image_content =
                         (uint64_t*)( raw_image_vs_PE_bias + address_in_image );
                uint64_t      correct_value     =
                         *raw_image_content - IMAGE_BASE + raw_image_vs_PE_bias;
                bool          should_patch      =
                         relocs[i].type == IMAGE_REL_BASED_DIR64;

                if (should_patch)
                        *raw_image_content = correct_value;
        }
}

/* This function interprets a segment as the .reloc section in a PE image. See
 * https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
 */
void parse_reloc_table(struct kexec_segment *segment, struct kimage* image)
{
        relocation_chunk_header_t* chunk       =
                        ( relocation_chunk_header_t* )segment->buf;
        unsigned long              segment_end =
                        (unsigned long)segment->buf + segment->bufsz;

        int i = 0;
        DebugMSG( "segment_end = 0x%lx\n", segment_end );
        while ( (unsigned long)chunk < segment_end )
        {
                DebugMSG( "chunk %d @ %px: va_offset = 0x%x chunk_size = 0x%x",
                          i++, chunk, chunk->va_offset, chunk->total_size );

                /* This is a hack. Ideally we should now the value of
                * NumberOfRelocations from the PE header. We are having
                * problems since SizeOfRawData > VirtualSize for the .reloc
                * section segment. */
                if (chunk->total_size == 0)
                        break;

                parse_chunk_relocations( chunk, image );

                chunk = ( relocation_chunk_header_t* )( (void*)chunk + chunk->total_size );
        }
}

 __attribute__((ms_abi)) efi_status_t efi_block_io_reset(EFI_BLOCK_IO_PROTOCOL* block_io)
{
        DebugMSG( "NOT IMPLEMENTED. device_id = %lld", block_io->device_id );
        return EFI_UNSUPPORTED;
}

 __attribute__((ms_abi)) efi_status_t efi_block_io_read_blocks(
                                            EFI_BLOCK_IO_PROTOCOL* block_io,
                                            UINT32                 MediaId,
                                            EFI_LBA                Lba,
                                            UINTN                  BufferSize,
                                            VOID                   *Buffer )
{
        UINTN block_size = block_io->Media->BlockSize;
        u64 offset       = Lba * block_size;
        int ret          = -1;

        DebugMSG( "device_id = %lld, MediaId = %d, block_io->file = %px "
                  "Lba = %lld, BufferSize = %lld, Buffer = %px",
                  block_io->device_id, MediaId, block_io->file,
                  Lba, BufferSize, Buffer );

        ret = vfs_read(block_io->file, Buffer, BufferSize, &offset);

        DumpBuffer( "Device read", Buffer, 32 );

        if (ret == BufferSize)
                return EFI_SUCCESS;

        DebugMSG( "ERROR: return value is different than requested size: "
                  "%d != %lld", ret, BufferSize );

        return EFI_DEVICE_ERROR;
}

 __attribute__((ms_abi)) efi_status_t efi_block_io_write_blocks(
                                            EFI_BLOCK_IO_PROTOCOL* block_io,
                                            UINT32                 MediaId,
                                            EFI_LBA                Lba,
                                            UINTN                  BufferSize,
                                            VOID                   *Buffer )
{
        UINTN block_size = block_io->Media->BlockSize;
        u64 offset       = Lba * block_size;
        int ret          = -1;

        DebugMSG( "device_id = %lld, MediaId = %d, "
                  "Lba = %lld, BufferSize = %lld",
                  block_io->device_id, MediaId, Lba, BufferSize );

        ret = vfs_write(block_io->file, Buffer, BufferSize, &offset);

        DumpBuffer( "Device write", Buffer, 32 );

        if (ret == BufferSize)
                return EFI_SUCCESS;

        DebugMSG( "ERROR: return value is different than requested size: "
                  "%d != %lld", ret, BufferSize );

        return EFI_DEVICE_ERROR;
}

 __attribute__((ms_abi)) efi_status_t efi_block_io_flush_blocks(EFI_BLOCK_IO_PROTOCOL* block_io)
{
        DebugMSG( "NOT IMPLEMENTED. device_id = %lld", block_io->device_id );
        return EFI_UNSUPPORTED;
}

EFI_BLOCK_IO_MEDIA raw_device_media = {
        .MediaId                           = 1,
        .RemovableMedia                    = 0,
        .MediaPresent                      = 1,
        .LogicalPartition                  = 0,
        .ReadOnly                          = 0,
        .WriteCaching                      = 0,
        .BlockSize                         = 512,
        .IoAlign                           = 0,
        .LastBlock                         = 104857599,
        .LowestAlignedLba                  = 0,
        .LogicalBlocksPerPhysicalBlock     = 0,
        .OptimalTransferLengthGranularity  = 0,
};

EFI_BLOCK_IO_MEDIA partition_1_media = {
        .MediaId                           = 1,
        .RemovableMedia                    = 0,
        .MediaPresent                      = 1,
        .LogicalPartition                  = 1,
        .ReadOnly                          = 0,
        .WriteCaching                      = 0,
        .BlockSize                         = 512,
        .IoAlign                           = 0,
        .LastBlock                         = 32733,
        .LowestAlignedLba                  = 0,
        .LogicalBlocksPerPhysicalBlock     = 0,
        .OptimalTransferLengthGranularity  = 0,
};

EFI_BLOCK_IO_MEDIA partition_2_media = {
        .MediaId                           = 1,
        .RemovableMedia                    = 0,
        .MediaPresent                      = 1,
        .LogicalPartition                  = 1,
        .ReadOnly                          = 0,
        .WriteCaching                      = 0,
        .BlockSize                         = 512,
        .IoAlign                           = 0,
        .LastBlock                         = 204799,
        .LowestAlignedLba                  = 0,
        .LogicalBlocksPerPhysicalBlock     = 0,
        .OptimalTransferLengthGranularity  = 0,
};

EFI_BLOCK_IO_MEDIA partition_3_media = {
        .MediaId                           = 1,
        .RemovableMedia                    = 0,
        .MediaPresent                      = 1,
        .LogicalPartition                  = 1,
        .ReadOnly                          = 0,
        .WriteCaching                      = 0,
        .BlockSize                         = 512,
        .IoAlign                           = 0,
        .LastBlock                         = 104617983,
        .LowestAlignedLba                  = 0,
        .LogicalBlocksPerPhysicalBlock     = 0,
        .OptimalTransferLengthGranularity  = 0,
};

EFI_BLOCK_IO_PROTOCOL raw_device_block_io = {
        .Revision = 0x20031,
        .Media = &raw_device_media,
        .Reset = efi_block_io_reset,
        .ReadBlocks = efi_block_io_read_blocks,
        .WriteBlocks = efi_block_io_write_blocks,
        .FlushBlocks = efi_block_io_flush_blocks,
        .device_id = 0
};

EFI_BLOCK_IO_PROTOCOL partition_1_block_io = {
        .Revision = 0x20031,
        .Media = &partition_1_media,
        .Reset = efi_block_io_reset,
        .ReadBlocks = efi_block_io_read_blocks,
        .WriteBlocks = efi_block_io_write_blocks,
        .FlushBlocks = efi_block_io_flush_blocks,
        .device_id = 1
};

EFI_BLOCK_IO_PROTOCOL partition_2_block_io = {
        .Revision = 0x20031,
        .Media = &partition_2_media,
        .Reset = efi_block_io_reset,
        .ReadBlocks = efi_block_io_read_blocks,
        .WriteBlocks = efi_block_io_write_blocks,
        .FlushBlocks = efi_block_io_flush_blocks,
        .device_id = 2
};

EFI_BLOCK_IO_PROTOCOL partition_3_block_io = {
        .Revision = 0x20031,
        .Media = &partition_3_media,
        .Reset = efi_block_io_reset,
        .ReadBlocks = efi_block_io_read_blocks,
        .WriteBlocks = efi_block_io_write_blocks,
        .FlushBlocks = efi_block_io_flush_blocks,
        .device_id = 3
};

/* Using *char[] is much more elegant, but it is prone to chnages of enum
 * values. Therefore we opted to use switch cases, automatically generated.
 * */
char* get_efi_mem_type_str( int mem_type )
{
        char *description = "<None>";

        switch(mem_type) {
        case EfiReservedMemoryType:
                description = "EfiReservedMemoryType";
                break;
        case EfiLoaderCode:
                description = "EfiLoaderCode";
                break;
        case EfiLoaderData:
                description = "EfiLoaderData";
                break;
        case EfiBootServicesCode:
                description = "EfiBootServicesCode";
                break;
        case EfiBootServicesData:
                description = "EfiBootServicesData";
                break;
        case EfiRuntimeServicesCode:
                description = "EfiRuntimeServicesCode";
                break;
        case EfiRuntimeServicesData:
                description = "EfiRuntimeServicesData";
                break;
        case EfiConventionalMemory:
                description = "EfiConventionalMemory";
                break;
        case EfiUnusableMemory:
                description = "EfiUnusableMemory";
                break;
        case EfiACPIReclaimMemory:
                description = "EfiACPIReclaimMemory";
                break;
        case EfiACPIMemoryNVS:
                description = "EfiACPIMemoryNVS";
                break;
        case EfiMemoryMappedIO:
                description = "EfiMemoryMappedIO";
                break;
        case EfiMemoryMappedIOPortSpace:
                description = "EfiMemoryMappedIOPortSpace";
                break;
        case EfiPalCode:
                description = "EfiPalCode";
                break;
        case EfiPersistentMemory:
                description = "EfiPersistentMemory";
                break;
        case EfiMaxMemoryType:
                description = "EfiMaxMemoryType";
                break;
        }

        return description;
}

char* get_efi_allocation_type_str( int allocation_type )
{
        char *description = "<None>";

        switch(allocation_type) {
        case AllocateAnyPages:
                description = "AllocateAnyPages";
                break;
        case AllocateMaxAddress:
                description = "AllocateMaxAddress";
                break;
        case AllocateAddress:
                description = "AllocateAddress";
                break;
        case MaxAllocateType:
                description = "MaxAllocateType";
                break;
        }

        return description;
}

/*********** Protocol handlers ****************/
void efi_set_wstring_from_ascii( CHAR16* dst, const char* src, size_t max_dst_size_bytes )
{
        int i = 0;
        char* dst_as_char = (char*)(dst);
        for (i = 0; i*2 < max_dst_size_bytes; i++ ) {
                dst_as_char[i*2] = src[i];
                dst_as_char[i*2+1] = '\0';

                if ( src[i] == '\0' )
                        break;
        }
}

/* The following struct is based on the reverse engineering of the LoadOptions
 * blob when observing a normal Windows EFI boot  */
typedef struct {
        CHAR8 header1[8];
        UINT32 val1;
        UINT32 val2;
        UINT32 val3;
        CHAR16 option[49];
        UINT16 val4;
        UINT32 val5;
        UINT32 val6;
        UINT32 val7;
        UINT32 val8;
} REVERSED_LOAD_OPTIONS;

REVERSED_LOAD_OPTIONS windows_load_options =  {
        .header1 = "WINDOWS",
        .val1 = 0x1,
        .val2 = sizeof(REVERSED_LOAD_OPTIONS),
        .val3 = sizeof(REVERSED_LOAD_OPTIONS) - 16,
        .option = {0},
        .val4 = 0x73,
        .val5 = 0x1,
        .val6 = 0x10,
        .val7 = 0x4,
        .val8 = 0x4ff7f
};

/* All device paths must end in this constant "device" node
 * See ch. 9.3 in
 * https://uefi.org/sites/default/files/resources/UEFI%20Spec%202_6.pdf */
EFI_DEVICE_PATH_PROTOCOL end_device_path_node = {
        .Type     = 0x7F,
        .SubType  = 0xFF,
        .Length   = {0x04, 0x00}
};

EFI_DEVICE_PATH_PROTOCOL* creat_windows_loader_device(void)
{
        /* TODO: The image file path should be passed along from user space. We
         * hard code it here. */
        const char* windows_loader_bootmg_file          =
                        "\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
        size_t sizeof_bootmg_file_path_as_wstring       =
            sizeof( CHAR16 ) * ( strlen( windows_loader_bootmg_file ) + 1 );
        EFI_DEVICE_PATH_PROTOCOL *windows_loader_device = NULL;
        uint16_t* pathLength                            = NULL;

        /* We now create a DevicePath of the "device" the started launching
         * Windows */
        windows_loader_device = (EFI_DEVICE_PATH_PROTOCOL*) vmalloc(
              sizeof( EFI_DEVICE_PATH_PROTOCOL ) +
              sizeof_bootmg_file_path_as_wstring +
              sizeof( end_device_path_node ) );
        DebugMSG( "windows_loader_device @ 0x%px", windows_loader_device );

        windows_loader_device->Type    = 0x4,    /* Media Device Path. */
        windows_loader_device->SubType = 0x4,    /* File Path. */
        pathLength                     = (uint16_t*)windows_loader_device->Length;
        *pathLength                    = sizeof( EFI_DEVICE_PATH_PROTOCOL ) +
                                                sizeof_bootmg_file_path_as_wstring;
        efi_set_wstring_from_ascii( (CHAR16*)windows_loader_device->data,
                                    windows_loader_bootmg_file,
                                    sizeof_bootmg_file_path_as_wstring );

        /* Terminate path with "End of Hardware Device Path": */
        memcpy( (uint8_t*)windows_loader_device + *pathLength,
                &end_device_path_node,
                sizeof( end_device_path_node ) );

        DumpBuffer( "Windows LoadedImage device", (uint8_t*)windows_loader_device,
                    *pathLength + sizeof( end_device_path_node ) );

        return windows_loader_device;
}

/* Below are mock devices to be used with OpenProtocol, LocateProtocol, etc.
 * They are all taken from a normal Windows EFI boot we logged. */
/* TODO: see TODO in efi_hook_LocateHandle. We should generate the device paths
 * on the fly. Here they are hardcoded based on our SPECIFIC disk image. */

/* This device path is the the raw hard drive.
   It contains just PciRoot(0x0)/Pci(0x4,0x0)/Scsi(0x1,0x0) */
uint8_t windows_raw_hd_device_path[30] = {
        /* ACPIPciRoot(0x0) */
        0x02, 0x01, 0x0C, 0x00, 0xD0, 0x41, 0x03, 0x0A,
        0x00, 0x00, 0x00, 0x00,

        /* Pci(0x4,0x0) */
        0x01, 0x01, 0x06, 0x00, 0x00, 0x04,

        /* Scsi(0x1,0x0) */
        0x03, 0x02, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,

        /* No partition */

        /* End Node */
        0x7F, 0xFF, 0x04, 0x00,
};

/* Device-path:
 *  PciRoot(0x0)/Pci(0x4,0x0)/Scsi(0x1,0x0)/
    HD(1,GPT,268DBAA1-CFA8-4D22-A3E9-BFECF74555DA,0x22,0x7FDE) */
uint8_t windows_partition_1_device_path[72] = {
        /* ACPIPciRoot(0x0) */
        0x02, 0x01, 0x0C, 0x00, 0xD0, 0x41, 0x03, 0x0A,
        0x00, 0x00, 0x00, 0x00,

        /* Pci(0x4,0x0) */
        0x01, 0x01, 0x06, 0x00, 0x00, 0x04,

        /* Scsi(0x1,0x0) */
        0x03, 0x02, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,

        /* HD(1,GPT,268DBAA1-CFA8-4D22-A3E9-BFECF74555DA,0x22,0x7FDE) */
        0x04, 0x01, 0x2A, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xDE, 0x7F, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xA1, 0xBA, 0x8D, 0x26,
        0xA8, 0xCF, 0x22, 0x4D, 0xA3, 0xE9, 0xBF, 0xEC,
        0xF7, 0x45, 0x55, 0xDA, 0x02, 0x02,

        /* End Node */
        0x7F, 0xFF, 0x04, 0x00,
};

/* PciRoot(0x0)/Pci(0x4,0x0)/Scsi(0x1,0x0)/
   HD(2,GPT,F6B5FF3C-2E8F-470D-98A8-D1110EDD1E1E,0x8000,0x32000) */
uint8_t windows_partition_2_device_path[72] = {
        /* PciRoot(0x0) */
        0x02, 0x01, 0x0C, 0x00,
        0xD0, 0x41, 0x03, 0x0A, 0x00, 0x00, 0x00, 0x00,

        /* Pci(0x4,0x0) */
        0x01, 0x01, 0x06, 0x00,
        0x00, 0x04,

        /* Scsi(0x1,0x0) */
        0x03, 0x02, 0x08, 0x00,
        0x01, 0x00, 0x00, 0x00,

        /* HD(2,GPT,F6B5FF3C-2E8F-470D-98A8-D1110EDD1E1E,0x8000,0x32000) */
        0x04, 0x01, 0x2A, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x03, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x3C, 0xFF, 0xB5, 0xF6,
        0x8F, 0x2E, 0x0D, 0x47, 0x98, 0xA8, 0xD1, 0x11,
        0x0E, 0xDD, 0x1E, 0x1E, 0x02, 0x02,

        /* End Node */
        0x7F, 0xFF, 0x04, 0x00,
};

/* PciRoot(0x0)/Pci(0x4,0x0)/Scsi(0x1,0x0)/
   HD(3,GPT,8B564A0A-EC1A-4653-9CF5-A691EA8C2D56,0x3A000,0x63C5800) */
uint8_t windows_partition_3_device_path[72] = {
        /* PciRoot(0x0) */
        0x02, 0x01, 0x0C, 0x00,
        0xD0, 0x41, 0x03, 0x0A, 0x00, 0x00, 0x00, 0x00,

        /* Pci(0x4,0x0) */
        0x01, 0x01, 0x06, 0x00,
        0x00, 0x04,

        /* Scsi(0x1,0x0) */
        0x03, 0x02, 0x08, 0x00,
        0x01, 0x00, 0x00, 0x00,

        /* HD(3,GPT,8B564A0A-EC1A-4653-9CF5-A691EA8C2D56,0x3A000,0x63C5800) */
        0x04, 0x01, 0x2A, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x03, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x3C, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x0A, 0x4A, 0x56, 0x8B,
        0x1A, 0xEC, 0x53, 0x46, 0x9C, 0xF5, 0xA6, 0x91,
        0xEA, 0x8C, 0x2D, 0x56, 0x02, 0x02,

        /* End Node */
        0x7F, 0xFF, 0x04, 0x00,
};

typedef struct {
        EFI_HANDLE            handle;
        size_t                size;
        uint8_t               *device_path;
        EFI_BLOCK_IO_PROTOCOL *block_io;
} DeviceData;


#define BOOT_RAW_DEVICE_HANDLE  0xDEADBEE0
#define BOOT_PARTITION_1_HANDLE (BOOT_RAW_DEVICE_HANDLE + 1)
#define BOOT_PARTITION_2_HANDLE (BOOT_RAW_DEVICE_HANDLE + 2)
#define BOOT_PARTITION_3_HANDLE (BOOT_RAW_DEVICE_HANDLE + 3)

#define GRAPHICS_HANDLE         ((EFI_HANDLE)0xCAFEBAB0)

DeviceData devices[4] = {
        { ( EFI_HANDLE )BOOT_RAW_DEVICE_HANDLE,
          sizeof( windows_raw_hd_device_path ),
          windows_raw_hd_device_path,
          &raw_device_block_io },
        { ( EFI_HANDLE )BOOT_PARTITION_1_HANDLE,
          sizeof( windows_partition_1_device_path ),
          windows_partition_1_device_path,
          &partition_1_block_io },
        { ( EFI_HANDLE )BOOT_PARTITION_2_HANDLE,
          sizeof( windows_partition_2_device_path ),
          windows_partition_2_device_path,
          &partition_2_block_io },
        { ( EFI_HANDLE )BOOT_PARTITION_3_HANDLE,
          sizeof( windows_partition_3_device_path ),
          windows_partition_3_device_path,
          &partition_3_block_io }
};

#define NUM_DEVICES (sizeof(devices) / sizeof(DeviceData))

EFI_LOADED_IMAGE_PROTOCOL windows_loaded_image = {
        .Revision         = 0x1000,
        .ParentHandle     = (void*)0x420000,
        .SystemTable      = NULL,
        .DeviceHandle     = ( EFI_HANDLE )BOOT_PARTITION_2_HANDLE,
        .FilePath         = NULL,
        .LoadOptionsSize  = sizeof(REVERSED_LOAD_OPTIONS),
        .LoadOptions      = NULL,
        .ImageBase        = NULL,
        .ImageSize        = 0,
        .ImageCodeType    = EfiLoaderCode,
        .ImageDataType    = EfiLoaderData,
        .Unload           = (void*)0x430000,
};

efi_system_table_t  fake_systab        = {0};
efi_boot_services_t linux_bootservices = {0};

__attribute__((ms_abi)) efi_status_t efi_hook_AllocatePages(
                                           EFI_ALLOCATE_TYPE     Type,
                                           EFI_MEMORY_TYPE       MemoryType,
                                           UINTN                 NumberOfPages,
                                           efi_physical_addr_t   *Memory );

#define NUM_PAGES(size) ((size-1) / PAGE_SIZE + 1)

void efi_setup_11_mapping( void* addr, size_t size );
void* efi_map_11_and_register_allocation(void* virt_kernel_addr, size_t size);

void kimage_load_pe(struct kimage *image, unsigned long nr_segments)
{
        unsigned long raw_image_relative_start;
        size_t        image_size = 0;
        int           i;
        efi_system_table_t* remapped_systab = NULL;

        /* Calculate total image size and allocate it: */
        for (i = 0; i < nr_segments; i++) {
                image_size += image->segment[i].memsz;
        }

        /* TODO: The followng base address should be taken from the segments:
         * image->raw_image = image->segment[0].mem;
           We need to fix u-root to have segment[0].mem be ImageBase */
        image->raw_image          = (void*)0x10000000;

        /* We allocate the raw_image in a 1:1 virt-to-phys mapping, so the code
         * can continue executing after Windows loader is taking over CR3 and
         * replaces the page table */
        efi_hook_AllocatePages( AllocateAddress, EfiLoaderCode,
                                NUM_PAGES( image_size ),
                                (efi_physical_addr_t*) &image->raw_image );

        /* ImageBase in objdump of efi image */
        /* TODO: So this is not really ImageBase. We should fix u-root. However,
         * we neex this reference value to calculate offsets inside our
         * allocation on image->raw_image. */
        image->raw_image_mem_base = image->segment[0].mem;

        raw_image_relative_start  = image->start - image->raw_image_mem_base;
        image->raw_image_start    = (void*)( image->raw_image + raw_image_relative_start );
        DebugMSG(  "image->raw_image = %px; "
                   "image->raw_image_mem_base = 0x%lx; "
                   "image_size = 0x%lx; "
                   "image->raw_image_start = %px\n",
                   image->raw_image,
                   image->raw_image_mem_base,
                   image_size,
                   image->raw_image_start );

        for (i = 0; i < nr_segments; i++) {
                kimage_load_pe_segment(image, &image->segment[i]);
        }

        windows_loaded_image.ImageBase   = (VOID*)image->raw_image;
        windows_loaded_image.ImageSize   = image_size;

        /* The system table must be accessible via physical addressing. We
         * therefore create 1:1 mapping of the location of it. */
        remapped_systab =
                (efi_system_table_t *)efi_map_11_and_register_allocation(
                                                        &fake_systab,
                                                        sizeof( fake_systab ));
        windows_loaded_image.SystemTable = remapped_systab;

       /* We now need to parse the relocation table of the PE and then patch the
        * efi binary. We assume that the last segment is the relocatiuon
        * segment. */
       /* TODO: Patch the relocations in user space. I.e., the segments being
        * sent to kexec_load should already be patched */
        parse_reloc_table( &image->segment[nr_segments-1], image );
}

efi_status_t efi_handle_protocol_LoadedImage( void* handle, void** interface )
{
        EFI_DEVICE_PATH_PROTOCOL *windows_loader_device = NULL;

        DebugMSG( "Called" );

        /* Inspecting a normal real run of Windows loading with EDK-II reveals
         * that the load options contain the following string.
         * Also see GUID_WINDOWS_BOOTMGR in
         * https://www.geoffchappell.com/notes/windows/boot/bcd/objects.htm
         * and in ReacOS (https://github.com/reactos) see
         * boot/environ/app/bootmgr/bootmgr.c */
        efi_set_wstring_from_ascii( windows_load_options.option,
                                    "BCDOBJECT={9dea862c-5cdd-4e70-acc1-f32b344d4795}",
                                    sizeof( windows_load_options.option ) );

        windows_loader_device            = creat_windows_loader_device();
        windows_loaded_image.FilePath    = windows_loader_device;
        windows_loaded_image.LoadOptions = &windows_load_options;
        DumpBuffer( "LoadOptions",
                    ( uint8_t* )&windows_load_options,
                    sizeof( windows_load_options ) );

        *interface = (void*)&windows_loaded_image;

        DebugMSG( "LoadedImage at %px;", *interface);
        DebugMSG( "Revision         = 0x%x;", windows_loaded_image.Revision);
        DebugMSG( "ParentHandle     = %px;", windows_loaded_image.ParentHandle);
        DebugMSG( "SystemTable      = %px;", windows_loaded_image.SystemTable );
        DebugMSG( "DeviceHandle     = %px;", windows_loaded_image.DeviceHandle );
        DebugMSG( "FilePath         = %px;", windows_loaded_image.FilePath );
        DebugMSG( "LoadOptionsSize  = %d;", windows_loaded_image.LoadOptionsSize );
        DebugMSG( "LoadOptions      = %px;", windows_loaded_image.LoadOptions );
        DebugMSG( "ImageBase        = %px;", windows_loaded_image.ImageBase );
        DebugMSG( "ImageSize        = 0x%llx;", windows_loaded_image.ImageSize );
        DebugMSG( "ImageCodeType    = 0x%x;", windows_loaded_image.ImageCodeType );
        DebugMSG( "ImageDataType    = 0x%x;", windows_loaded_image.ImageDataType );
        DebugMSG( "Unload           = %px;", windows_loaded_image.Unload);

        return EFI_SUCCESS;
}

__attribute__((ms_abi)) efi_status_t efi_hook_AllocatePool(
                        EFI_MEMORY_TYPE pool_type,
                        unsigned long  size,
                        void           **buffer );

void efi_setup_11_mapping_physical_addr( unsigned long start,
                                         unsigned long end );
void Dump_fb_bitfield( struct fb_bitfield * bf, char* title )
{
        DebugMSG( "%s: offset = %d, length = %d, msg_right = %d",
                  title, bf->offset, bf->length, bf->msb_right );
}

EFI_GRAPHICS_OUTPUT_MODE_INFORMATION graphics_info   = {0};
EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE    graphics_mode   = {0};
EFI_GRAPHICS_OUTPUT_PROTOCOL         graphics_output = {0};
EFI_GRAPHICS_OUTPUT_PROTOCOL*        graphics_output_remapped = NULL;

void efi_hook_query_mode(void)
{
        DebugMSG( "Unexpected call!" );
        while (1) {}
}

void efi_hook_set_mode(void)
{
        DebugMSG( "Unexpected call!" );
        while (1) {}
}

void efi_hook_blt(void)
{
        DebugMSG( "Unexpected call!" );
        while (1) {}
}

void efi_dump_screen_info(struct fb_var_screeninfo *fvsi,
                           struct fb_fix_screeninfo *ffsi )
{
        DebugMSG( "xres            = %d", fvsi->xres );
        DebugMSG( "yres            = %d", fvsi->yres );
        DebugMSG( "xres_virtual    = %d", fvsi->xres_virtual );
        DebugMSG( "yres_virtual    = %d", fvsi->yres_virtual );
        DebugMSG( "xoffset         = %d", fvsi->xoffset );
        DebugMSG( "yoffset         = %d", fvsi->yoffset );
        DebugMSG( "bits_per_pixel  = %d", fvsi->bits_per_pixel );
        DebugMSG( "grayscale       = %d", fvsi->grayscale );
        Dump_fb_bitfield( &fvsi->red,   "Red" );
        Dump_fb_bitfield( &fvsi->green, "Green" );
        Dump_fb_bitfield( &fvsi->blue,  "Blue" );
        Dump_fb_bitfield( &fvsi->transp,"transp" );

        DebugMSG( "id = %s", ffsi->id );
        DebugMSG( "smmio_start  @ 0x%lx",  ffsi->smem_start );
        DebugMSG( "smmio_len    = %d",    ffsi->smem_len );
        DebugMSG( "mmio_start   @ 0x%lx",  ffsi->mmio_start );
        DebugMSG( "mmio_len     = %d",    ffsi->mmio_len );
        DebugMSG( "line_length  = %d",    ffsi->line_length );
        DebugMSG( "type         = 0x%x",  ffsi->type );
        DebugMSG( "visual       = 0x%x",  ffsi->visual );
}

void efi_demonstrate_graphics(struct fb_var_screeninfo *fvsi,
                              struct fb_fix_screeninfo *ffsi )
{
        /* ffsi->smem_start is now addressable, since it's mapped 1:1 */
        uint8_t* frame_buffer = (uint8_t*)ffsi->smem_start;
        int x,y;

        for( y = 0; y < fvsi->yres; y++ ) {
                for( x = 0; x < fvsi->xres; x++ ) {
                        size_t offset = y*ffsi->line_length +
                                        ( x * (fvsi->bits_per_pixel / 8) );
                        uint32_t* pixel = (uint32_t*)&frame_buffer[offset];
                        *pixel = 0;
                        if (x / 100 % 2 == 0)
                                *pixel |= 255 << fvsi->red.offset;
                        if (x / 100 % 3 == 0)
                                *pixel |= 255 << fvsi->green.offset;
                        if (x / 100 % 4 == 0)
                                *pixel |= 255 << fvsi->blue.offset;
                }
        }
}

void efi_initialize_graphics(void)
{
        struct file *fb_file            = NULL;
        int flags                       = O_RDWR;
        int mode                        = 0;
        struct fb_var_screeninfo *fvsi  = NULL;
        struct fb_fix_screeninfo *ffsi  = NULL;
        int ret                         = 0;
        uint8_t* frame_buffer           = NULL;

        /* We need to allocate fvsi and ffsi in a "user space" address to be
         * used later with ioctl */
        efi_hook_AllocatePool( EfiRuntimeServicesData,
                               NUM_PAGES( sizeof( struct fb_var_screeninfo ) +
                                          sizeof( struct fb_fix_screeninfo )),
                               (void**)&fvsi );
        memset( fvsi, 0, sizeof( struct fb_var_screeninfo ) );

        ffsi = (void*)((uint8_t*)fvsi + sizeof( struct fb_fix_screeninfo ));
        memset( ffsi, 0, sizeof( struct fb_fix_screeninfo ) );

        DebugMSG( "fvsi = %px, ffsi = %px", fvsi, ffsi );

        /* We open the frame buffer device, then call IOCTL to get its info */
        fb_file = filp_open("/dev/fb0", flags, mode);
        DebugMSG( "fb_file = %px", fb_file );

        ret = vfs_ioctl( fb_file, FBIOGET_VSCREENINFO, (unsigned long)fvsi );
        DebugMSG( "ioctl FBIOGET_VSCREENINFO ret = %d", ret );

        ret = vfs_ioctl( fb_file, FBIOGET_FSCREENINFO, (unsigned long)ffsi );
        DebugMSG( "ioctl FBIOGET_FSCREENINFO ret = %d", ret );

        efi_dump_screen_info( fvsi, ffsi );

        /* We need to map the frame buffer into 1:1 virt-phys memory */
        efi_setup_11_mapping_physical_addr( ffsi->smem_start,
                                            ffsi->smem_start + ffsi->smem_len );

        efi_demonstrate_graphics( fvsi, ffsi );

        /* Now setup the required EFI structures so we can reply to Windows
         * loader. */
        graphics_info.Version = 0;
        graphics_info.HorizontalResolution = fvsi->xres;
        graphics_info.VerticalResolution   = fvsi->yres;
        graphics_info.PixelFormat = PixelBlueGreenRedReserved8BitPerColor;
        /* graphics_info.PixelInformation is NOT needed */
        graphics_info.PixelsPerScanLine = ffsi->line_length /
                                          (fvsi->bits_per_pixel / 8) ;

        frame_buffer             = (uint8_t*)ffsi->smem_start;
        graphics_mode.MaxMode    = 1;
        graphics_mode.Mode       = 0;
        graphics_mode.Info       = efi_map_11_and_register_allocation(
                                      &graphics_info, sizeof( graphics_info ) );
        graphics_mode.SizeOfInfo = sizeof( graphics_info );
        graphics_mode.FrameBufferBase = (EFI_PHYSICAL_ADDRESS)frame_buffer;
        graphics_mode.FrameBufferSize = ffsi->smem_len;

        graphics_output.QueryMode = efi_hook_query_mode;
        graphics_output.SetMode   = efi_hook_set_mode;
        graphics_output.Blt       = efi_hook_blt;
        graphics_output.Mode      = efi_map_11_and_register_allocation(
                                     &graphics_mode, sizeof( graphics_mode ) );

        graphics_output_remapped = efi_map_11_and_register_allocation(
                                  &graphics_output, sizeof( graphics_output ) );

        DebugMSG( "graphics_output_remapped @ %px", graphics_output_remapped );
}

efi_status_t efi_handle_protocol_graphics( void** interface )
{
        DebugMSG( "interface = %px", interface );

        if (graphics_output_remapped == NULL)
                efi_initialize_graphics();

        *interface = graphics_output_remapped;

        DebugMSG( "*interface = %px", *interface );
        return EFI_SUCCESS;
}

#define INVALID_DEVICE_ID -1
int get_device_id( void* handle )
{
        int i = 0;
        for (i = 0; i < NUM_DEVICES; i++ ) {
                if (devices[i].handle == handle) {
                        DebugMSG( "Found handle at devices[%d]", i );
                        return i;
                }
        }

        return INVALID_DEVICE_ID;
}

efi_status_t efi_handle_protocol_DevicePath( void* handle, void** interface )
{
        int device_id = get_device_id( handle );

        DebugMSG( "handle = %px", handle );

        if (device_id == INVALID_DEVICE_ID) {
                DebugMSG( "unknown handle %px", handle );

                return EFI_UNSUPPORTED;
        }

        *interface = efi_map_11_and_register_allocation(
                                        devices[device_id].device_path,
                                        devices[device_id].size );
        DumpBuffer( "Device Path",
                    (uint8_t*) *interface, devices[device_id].size );

        return EFI_SUCCESS;
}

efi_status_t efi_handle_protocol_BlockIO( void* handle, void** interface )
{
        int device_id                   = get_device_id( handle );
        EFI_BLOCK_IO_PROTOCOL* block_io = NULL;
        char device_path_str[64]        = {0};
        int flags                       = O_RDWR | O_SYNC;
        int mode                        = 0;

        DebugMSG( "handle = %px", handle );

        if (device_id == INVALID_DEVICE_ID) {
                DebugMSG( "unknown handle %px", handle );

                return EFI_UNSUPPORTED;
        }

        *interface = efi_map_11_and_register_allocation(
                                        devices[device_id].block_io,
                                        sizeof( *devices[device_id].block_io ) );
        block_io = (EFI_BLOCK_IO_PROTOCOL*)(*interface);

        /* We need to fix block_io->Media to point into 1:1 mapped memory. The
         * macro access_ok tells us if Media is already in user space, which is
         * the general area of physical addresses. */
        if (!access_ok( block_io->Media, sizeof( *(block_io->Media) ) )) {
                DebugMSG( "Media @ %px; converting to 1:1 mapped address",
                          block_io->Media );
                block_io->Media = efi_map_11_and_register_allocation(
                                        block_io->Media,
                                        sizeof( *(block_io->Media) ) );
        }
        else {
                DebugMSG ("Media @ %px - already in 1:1 mapped area",
                          block_io->Media );
        }

        if (device_id == 0)
                strcpy( device_path_str, "/dev/sda" );
        else
                sprintf( device_path_str, "/dev/sda%d", device_id );

        if (block_io->file != NULL) {
                DebugMSG( "Device %s is already open", device_path_str );
                return EFI_SUCCESS;
        }

        block_io->file = filp_open(device_path_str, flags, mode);
        DebugMSG( "Openning %s --> fp = %px", device_path_str, block_io->file );

        if (block_io->file == NULL) {
                DebugMSG( "ERROR: Can't open device!" );
                return EFI_DEVICE_ERROR;
        }

        return EFI_SUCCESS;
}

__attribute__((ms_abi)) efi_status_t efi_conin_hook_Reset(void)
{
         DebugMSG( "ConIn was called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_conin_hook_ReadKeyStrokeEx(void)
{
         DebugMSG( "ConIn was called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_conin_hook_SetState(
                                        void* this_protocol,
                                        EFI_KEY_TOGGLE_STATE* KeyToggleState )
{
         DebugMSG( "KeyToggleState = 0x%x", *KeyToggleState );

         return EFI_SUCCESS;
}

__attribute__((ms_abi)) efi_status_t efi_conin_hook_RegisterKeyNotify(void)
{
         DebugMSG( "ConIn was called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_conin_hook_UnregisterKeyNotify(void)
{
         DebugMSG( "ConIn was called" );

         return EFI_UNSUPPORTED;
}

#define CON_IN_HANDLE         0xdeadbeefcafebab1
#define WAIT_FOR_KEY_EVENT_ID 0xABCDEFABCDEF2345

EFI_SIMPLE_TEXT_EX_INPUT_PROTOCOL con_in = {
        .Reset               = efi_conin_hook_Reset,
        .ReadKeyStrokeEx     = efi_conin_hook_ReadKeyStrokeEx,
        .WaitForKeyEx        = (void*)WAIT_FOR_KEY_EVENT_ID,
        .SetState            = efi_conin_hook_SetState,
        .RegisterKeyNotify   = efi_conin_hook_RegisterKeyNotify,
        .UnregisterKeyNotify = efi_conin_hook_UnregisterKeyNotify
};

efi_status_t efi_handle_protocol_SimpleTextInputExProtocol( void*  handle,
                                                            void** interface )
{
        DebugMSG( "handle = %px", handle );

        if (handle != (void*)CON_IN_HANDLE) {
                DebugMSG( "unknown handle %px", handle );

                return EFI_UNSUPPORTED;
        }

        *interface = efi_map_11_and_register_allocation( &con_in,
                                                         sizeof( con_in ) );

        return EFI_SUCCESS;
}

/*********** End of protocols *****************/
/* This function receives a virtual addr and created a 1:1 mapping between
 * virtual memory to the actual physical address that belongs to addr */
/* start & end are physical addresses */
void efi_setup_11_mapping_physical_addr( unsigned long start, unsigned long end )
{
        unsigned long mmap_ret  = 0;
        unsigned long populate  = 0;
        int           remap_err = 0;

        struct mm_struct      *mm  = current->mm;
        struct vm_area_struct *vma = NULL;

        vma = find_vma(mm, start) ;
        DebugMSG( "start = 0x%lx, end = 0x%lx, vma->vm_start = 0x%lx; "
                  "vma->vm_end = 0x%lx",
                  start, end, vma->vm_start, vma->vm_end );

        if ( vma->vm_start <= start ) {
                /* vma already exists. We expect the flags to contain VM_PFNMAP
                 * which means we already created 1:1 mapping for this address
                 * Otherwise - something is wrong. Specifically, the user-space
                 * memory was probably already in use. */

                /* The following flags are set by remap_pfn_range */
                u32  pfn_remapping_flags    =
                                VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;

                bool memory_is_pfn_remapped =
                                vma->vm_flags & pfn_remapping_flags;
                BUG_ON( ! memory_is_pfn_remapped );

                if ( vma->vm_end >= end ) {
                        /* We already mapped these addresses as 1:1 */
                        DebugMSG( "These addresses should already be 1:1 mapped. Skipping." );
                        return;
                }

                /* If we got here, it means that vma->vm_end < end. We need to
                 * extend the vma */
                start = vma->vm_end;

                /* end must be smaller than the vma end: */
                /* BUG_ON( vma->vm_end < end ); */
        }

        /* TODO: should we make sure size of a multiple of PAGE_SIZE? */
        /* BUG_ON( size % PAGE_SIZE != 0 ); */

        /* The mm semaphore is required for both do_mmap AND remap_pfn_range */
        down_write(&mm->mmap_sem);

        /* First, we need to add a vma structure corresponding to the
         * user-space address matching the physical address */
        mmap_ret = do_mmap( NULL,
                            start,
                            end - start,
                            PROT_READ | PROT_WRITE,
                            MAP_FIXED | MAP_PRIVATE,
                            VM_READ | VM_WRITE,
                            0,
                            &populate,
                            NULL /* struct list_head *u */
        );
        DebugMSG( "mmap_ret = 0x%lx; populate = 0x%lx", mmap_ret, populate );

        /* Fetch the vma struct for our newly allocated user-space memory */
        vma = find_vma(mm, start) ;
        DebugMSG( "vma->vm_start = 0x%lx; vma->vm_end = 0x%lx",
                  vma->vm_start, vma->vm_end );

        /* Adjust end to fit the entire vma */
        if (vma->vm_end > end)
                end = vma->vm_end;

        /* Next,remap the physical memory, allocated to the kernel,
         * to the user-space */
        remap_err = remap_pfn_range( vma, start, start >> PAGE_SHIFT,
                                     end - start, PAGE_KERNEL_EXEC );
        DebugMSG( "remap_pfn_range -> %d", remap_err );

        up_write(&mm->mmap_sem);
}

void efi_setup_11_mapping( void* addr, size_t size )
{
        unsigned long start     = ALIGN_DOWN( virt_to_phys(addr), PAGE_SIZE);
        unsigned long end       = ALIGN(virt_to_phys(addr) + size, PAGE_SIZE);

        efi_setup_11_mapping_physical_addr( start, end );
}
#define EFI_MAX_MEMORY_MAPPINGS 1000
#define EFI_DEFAULT_MEM_ATTRIBUTES ( EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB )

typedef struct {
	u32 type;
	u32 pad;
	u64 phys_addr;
	u64 virt_addr;
	u64 num_pages;
	u64 attribute;
    u64 pad2;
} EFI_MEMORY_DESCRIPTOR;

typedef struct {
        EFI_MEMORY_DESCRIPTOR mem_descriptor;
        struct list_head      list;
} MemoryAllocation;

LIST_HEAD( efi_memory_mappings );
uint64_t efi_mem_map_epoch = 0;

MemoryAllocation* efi_find_mem_allocation( unsigned long phys_addr )
{
        EFI_MEMORY_DESCRIPTOR *mem_map      = NULL;
        MemoryAllocation      *mem_alloc    = NULL;
        unsigned long         end_of_region = 0;

        list_for_each_entry( mem_alloc, &efi_memory_mappings, list ) {
                mem_map       = &mem_alloc->mem_descriptor;
                end_of_region = mem_map->phys_addr +
                                mem_map->num_pages * PAGE_SIZE;

                if (phys_addr < mem_map->phys_addr ||
                    phys_addr >= end_of_region)
                        continue;

                DebugMSG( "Located mapping phys->virt: 0x%llx->0x%llx "
                          "(%lld pages)",
                          mem_map->phys_addr, mem_map->virt_addr,
                          mem_map->num_pages);

                return mem_alloc;
        }

        DebugMSG( "Couldn't find mapping." );
        return NULL;
}

MemoryAllocation* efi_mem_allocation_build_chunk(
                                       EFI_MEMORY_TYPE       MemoryType,
                                       unsigned long         phys_addr,
                                       UINTN                 NumberOfPages )
{
        MemoryAllocation *mem_alloc    =
                        kmalloc( sizeof(MemoryAllocation), GFP_KERNEL );
        EFI_MEMORY_DESCRIPTOR *mem_map = NULL;

        BUG_ON( mem_alloc == NULL );

        DebugMSG( "Creating chunk of %lld pages of type %s @ 0x%lx",
                   NumberOfPages, get_efi_mem_type_str( MemoryType ),
                   phys_addr );

        mem_map = &mem_alloc->mem_descriptor;
        INIT_LIST_HEAD( &mem_alloc->list );

        memset( mem_map, 0, sizeof( *mem_map ) );
        mem_map->type      = MemoryType;
        mem_map->pad       = 0;
        mem_map->phys_addr = phys_addr;
        mem_map->virt_addr = 0;  // Similar to EDK-II code
        mem_map->num_pages = NumberOfPages;
        mem_map->attribute = EFI_DEFAULT_MEM_ATTRIBUTES;

        if (MemoryType == EfiRuntimeServicesCode ||
            MemoryType == EfiRuntimeServicesData)
                mem_map->attribute |= EFI_MEMORY_RUNTIME;

        return mem_alloc;
}

void efi_maybe_coalesce_chunks( MemoryAllocation *mem_alloc );

/* Register new mem allocation. The allocation is brand new and there is no
 * region in &efi_memory_mappings, which overlaps with it */
void efi_register_new_phys_mem_allocation( EFI_MEMORY_TYPE       MemoryType,
                                           UINTN                 NumberOfPages,
                                           unsigned long         phys_addr )
{
        MemoryAllocation *cur_alloc    = efi_mem_allocation_build_chunk(
                                         MemoryType, phys_addr, NumberOfPages );
        MemoryAllocation *next_alloc   = NULL;
        EFI_MEMORY_DESCRIPTOR *mem_map = NULL;

        if (list_empty(&efi_memory_mappings)) {
                list_add_tail( &cur_alloc->list, &efi_memory_mappings);
                goto out;
        }

        /* Assuming the list is already sorted, we need to find the proper
         * location to insert the new chunk to keep the list sorted. We know
         * that the new allocating is not inside an existing one. Therefore, we
         * just need to find a chunk with start addr bigger than the new
         * allocation. */
        list_for_each_entry( next_alloc, &efi_memory_mappings, list ) {
                mem_map       = &next_alloc->mem_descriptor;
                if (mem_map->phys_addr > phys_addr ) {
                        list_add( &cur_alloc->list, next_alloc->list.prev );
                        goto out;
                }
        }

        /* If we got her, it means that mem_map->phys_addr is bigger than all
         * existing chunks in the list. We therefore add the new chunk at the
         * end of the list. */
        list_add_tail( &cur_alloc->list, &efi_memory_mappings);

out:
        efi_maybe_coalesce_chunks( cur_alloc );
}

void efi_register_phys_mem_allocation_inside_existing(
                                       EFI_MEMORY_TYPE       MemoryType,
                                       UINTN                 NumberOfPages,
                                       unsigned long         phys_addr,
                                       MemoryAllocation*     mem_alloc )
{
        EFI_MEMORY_DESCRIPTOR *mem_map        = &mem_alloc->mem_descriptor;
        unsigned long end_of_requested_region = phys_addr +
                                                NumberOfPages * PAGE_SIZE;
        unsigned long end_of_existing_region  = mem_map->phys_addr +
                                                mem_map->num_pages * PAGE_SIZE;
        MemoryAllocation *prev_chunk          = NULL;
        MemoryAllocation *next_chunk          = NULL;

        /* We need to split the allocation we found into up to 3 pieces:
         * prev, new, next chunks. We will reuse the existing chunk for the new
         * requested allocation. prev & next are the residues of the preexisting
         * block. */
        DebugMSG( "phys_addr = 0x%lx, mem_map->phys_addr = 0x%llx, "
                  "end_of_existing_region = 0x%lx, "
                  "end_of_requested_region = 0x%lx",
                  phys_addr, mem_map->phys_addr,
                  end_of_existing_region, end_of_requested_region);

        BUG_ON( end_of_requested_region > end_of_existing_region );

        if (phys_addr > mem_map->phys_addr) {
                size_t prev_chunk_size = phys_addr - mem_map->phys_addr;
                BUG_ON( prev_chunk_size % PAGE_SIZE != 0 );
                prev_chunk = efi_mem_allocation_build_chunk(
                                mem_map->type,
                                mem_map->phys_addr,
                                NUM_PAGES(prev_chunk_size));

                mem_map->num_pages = mem_map->num_pages -
                                     NUM_PAGES(prev_chunk_size);
                DebugMSG( "Reduced num_pages to %lld", mem_map->num_pages );
        }

        if (end_of_requested_region < end_of_existing_region) {
                size_t next_chunk_size = end_of_existing_region -
                                         end_of_requested_region;
                BUG_ON( next_chunk_size % PAGE_SIZE != 0 );
                next_chunk = efi_mem_allocation_build_chunk(
                                mem_map->type,
                                end_of_requested_region, /* start of next cunk */
                                NUM_PAGES(next_chunk_size)) ;

                mem_map->num_pages = mem_map->num_pages -
                                     NUM_PAGES(next_chunk_size);
                DebugMSG( "Reduced num_pages to %lld", mem_map->num_pages );
        }

        /* After all the arithmetics the middle chunk should be exactly the size
         * of the requested allocation */
        BUG_ON( mem_map->num_pages != NumberOfPages );

        /* Set the middle chunk with the type of the new region and addr */
        mem_map->type      = MemoryType;
        mem_map->phys_addr = phys_addr;

        if (prev_chunk != NULL)
                list_add( &prev_chunk->list, mem_alloc->list.prev );

        if (next_chunk != NULL)
                list_add( &next_chunk->list, &mem_alloc->list );

        efi_maybe_coalesce_chunks( mem_alloc );
}

void efi_print_memory_map(void);
void efi_register_phys_mem_allocation( EFI_MEMORY_TYPE       MemoryType,
                                       UINTN                 NumberOfPages,
                                       unsigned long         phys_addr )

{
        EFI_MEMORY_DESCRIPTOR *mem_map   = NULL;
        MemoryAllocation      *mem_alloc = NULL;

        DebugMSG( "Registering %lld pages of type %s @ 0x%lx",
                   NumberOfPages, get_efi_mem_type_str( MemoryType ),
                   phys_addr );

        /* We increment the version of mem_map of every call to
         * efi_register_new_phys_mem_allocation */
        efi_mem_map_epoch++;

        mem_alloc = efi_find_mem_allocation( phys_addr );

        if (mem_alloc == NULL) {
                /* This is a brand new allocation. No overlapping with existing
                 * allocation */
                efi_register_new_phys_mem_allocation( MemoryType, NumberOfPages,
                                                      phys_addr );
                return;
        }

        /* If we got here, it means this allocation request is overlapping with
         * and existing one */
        mem_map = &mem_alloc->mem_descriptor;
        if (mem_map->phys_addr == phys_addr &&
            mem_map->num_pages == NumberOfPages) {
                /* BUG_ON( mem_map->type != MemoryType ); */

                mem_map->type = MemoryType;
                efi_maybe_coalesce_chunks( mem_alloc );

                DebugMSG( "Same allocation detected"  );
                /* This is exactly the same allocation. Nothing to be done */
                return;
        }

        efi_register_phys_mem_allocation_inside_existing( MemoryType,
                                                          NumberOfPages,
                                                          phys_addr,
                                                          mem_alloc );
        /* efi_print_memory_map(); */
}


void efi_register_mem_allocation(  EFI_MEMORY_TYPE       MemoryType,
                                   UINTN                 NumberOfPages,
                                   void*                 allocation )
{
        DebugMSG( "Registering %lld pages of type %s @ %px",
                   NumberOfPages, get_efi_mem_type_str( MemoryType ),
                   allocation );

        efi_register_phys_mem_allocation( MemoryType,
                                          NumberOfPages,
                                          virt_to_phys( allocation ) );
}

/* Coalesce two chunks of EfiConventionalMemory. They are assumed to be
 * consecutive in the mappings list, and both represent the same memory time. */
MemoryAllocation* efi_coalesce_2_chunks( MemoryAllocation *first_alloc,
                                         MemoryAllocation *second_alloc )
{
        efi_print_memory_map();
        DebugMSG( "Coalescing chunk starting at 0x%llx with "
                  " chunk starting at 0x%llx",
                  first_alloc->mem_descriptor.phys_addr,
                  second_alloc->mem_descriptor.phys_addr );

        first_alloc->mem_descriptor.num_pages +=
                        second_alloc->mem_descriptor.num_pages;

        list_del( &second_alloc->list );

        return first_alloc;
}

/* Check if we can coalesce unused memory chunks in memory map */
void efi_maybe_coalesce_chunks( MemoryAllocation *mem_alloc )
{
        EFI_MEMORY_DESCRIPTOR *mem_map = &mem_alloc->mem_descriptor;
        MemoryAllocation *prev_alloc   = NULL;
        MemoryAllocation *next_alloc   = NULL;
        MemoryAllocation *new_alloc    = mem_alloc;
        unsigned long    end_of_region = 0;

        /* BUG_ON( mem_map->type != EfiConventionalMemory ); */

        /* If we are not the first item on the list, get the previous one */
        if (list_first_entry( &efi_memory_mappings, MemoryAllocation ,list )
            != mem_alloc)
                prev_alloc = list_prev_entry( mem_alloc, list );

        if (! list_is_last( &mem_alloc->list, &efi_memory_mappings))
                next_alloc = list_next_entry( mem_alloc, list );

        if (prev_alloc != NULL) {
                EFI_MEMORY_DESCRIPTOR *prev_map = &prev_alloc->mem_descriptor;
                end_of_region = prev_map->phys_addr +
                                prev_map->num_pages * PAGE_SIZE;

                /* If regions are adjacent, and both free - coalesce! */
                if (end_of_region  == mem_map->phys_addr &&
                    prev_map->type == mem_map->type )
                        new_alloc = efi_coalesce_2_chunks( prev_alloc,
                                                           mem_alloc );
        }

        if (next_alloc != NULL) {
                EFI_MEMORY_DESCRIPTOR *next_map = &next_alloc->mem_descriptor;
                end_of_region = mem_map->phys_addr +
                                mem_map->num_pages * PAGE_SIZE;

                /* If regions are adjacent, and both free - coalesce! */
                /* new_alloc is either the original mem_map or the amalgamation
                 * of prev and the original mem_map */
                if (end_of_region  == next_map->phys_addr &&
                    next_map->type == mem_map->type )
                        efi_coalesce_2_chunks( new_alloc, next_alloc );
        }
}


efi_status_t efi_unregister_allocation( efi_physical_addr_t PhysicalAddress,
                                        UINTN               NumberOfPages )
{
        EFI_MEMORY_DESCRIPTOR *mem_map          = NULL;
        u64                   offset_in_mapping = 0;
        efi_physical_addr_t   end_of_region     = 0;

        MemoryAllocation *mem_alloc = NULL;
        list_for_each_entry( mem_alloc, &efi_memory_mappings, list ) {
                mem_map = &mem_alloc->mem_descriptor;

                end_of_region = mem_map->phys_addr +
                                mem_map->num_pages * PAGE_SIZE;
                if (PhysicalAddress < mem_map->phys_addr ||
                    PhysicalAddress >= end_of_region)
                        continue;

                offset_in_mapping = PhysicalAddress - mem_map->phys_addr;

                DebugMSG( "Located mapping phys->virt: 0x%llx->0x%llx "
                          "(%lld pages, offset=0x%llx)",
                          mem_map->phys_addr, mem_map->virt_addr,
                          NumberOfPages, offset_in_mapping );

                if (offset_in_mapping != 0 ||
                    mem_map->num_pages != NumberOfPages ) {
                       DebugMSG( "Free request is different than allocation!!" );
                       /* TODO: handle greacefully. For example, allow
                        * reclaiming parts or regions */
                       return EFI_INVALID_PARAMETER;
                }

                mem_map->type = EfiConventionalMemory; /* Memory is free now */
                efi_maybe_coalesce_chunks( mem_alloc );

                return EFI_SUCCESS;
        }

        DebugMSG( "Couldn't find mapping." );
        return EFI_INVALID_PARAMETER;
}

/*********** EFI hooks ************************/
__attribute__((ms_abi)) efi_status_t efi_hook_RaiseTPL(void)
{
         DebugMSG( "BOOT SERVICE #0 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_RestoreTPL(void)
{
         DebugMSG( "BOOT SERVICE #1 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_FreePages(
                                          efi_physical_addr_t PhysicalAddress,
                                          UINTN               NumberOfPages )
{
        efi_status_t status = EFI_SUCCESS;

        DebugMSG( "Physical address = 0x%llx, NumberOfPages = %lld",
                   PhysicalAddress, NumberOfPages );

        status = efi_unregister_allocation( PhysicalAddress, NumberOfPages );
        efi_print_memory_map();
        return status;
}

size_t efi_get_mem_map_size(void)
{
        u32              num_mem_allocations = 0;
        struct list_head *position           = NULL;

        list_for_each ( position , &efi_memory_mappings )
        {
                num_mem_allocations++;
        }

        DebugMSG( "Number of entries in MemMap: %d", num_mem_allocations );

        return num_mem_allocations * sizeof( EFI_MEMORY_DESCRIPTOR );
}

void efi_print_memory_map(void)
{
        MemoryAllocation      *mem_alloc           = NULL;
        EFI_MEMORY_DESCRIPTOR *mem_map             = NULL;
        int                   entryIdx             = 0;

        list_for_each_entry( mem_alloc, &efi_memory_mappings, list ) {
                mem_map = &mem_alloc->mem_descriptor;

                DebugMSG( "%3d: %-25s, 0x%16llx -> 0x%16llx, %5lld, 0x%016llx",
                    entryIdx++, get_efi_mem_type_str(mem_map->type),
                    mem_map->phys_addr, mem_map->virt_addr,
                    mem_map->num_pages, mem_map->attribute );
        }
}

__attribute__((ms_abi)) efi_status_t efi_hook_GetMemoryMap(
                                     unsigned long         *MemoryMapSize,
                                     EFI_MEMORY_DESCRIPTOR *MemoryMap,
                                     unsigned long         *MapKey,
                                     unsigned long         *DescriptorSize,
                                     u32                   *DescriptorVersion)

{
        size_t                current_mapping_size = efi_get_mem_map_size();
        int                   entryIdx             = 0;
        EFI_MEMORY_DESCRIPTOR *mem_map             = NULL;
        efi_status_t          status               = EFI_SUCCESS;
        uint8_t*              current_offset       = ( uint8_t* )MemoryMap;
        MemoryAllocation      *mem_alloc           = NULL;

        *DescriptorVersion        = 1;
        *DescriptorSize           = sizeof( EFI_MEMORY_DESCRIPTOR );

        DebugMSG( "MemoryMapSize @ %px "
                  "MemoryMap @ %px "
                  "DescriptorSize = %ld "
                  "DescriptorVersion = %d",
                  MemoryMapSize, MemoryMap,
                  *DescriptorSize, *DescriptorVersion );

        if (*MemoryMapSize < current_mapping_size ) {
                unsigned long mmap_size_in  = *MemoryMapSize;
                *MemoryMapSize              = current_mapping_size;
                status                      = EFI_BUFFER_TOO_SMALL;
                DebugMSG( "Buffer too small. MemoryMapSize = %ld bytes, "
                          "need %ld. status = 0x%lx",
                           mmap_size_in, *MemoryMapSize, status );

                return status;
        }


        list_for_each_entry( mem_alloc, &efi_memory_mappings, list ) {
                mem_map = &mem_alloc->mem_descriptor;
                memcpy( current_offset, mem_map, sizeof( *mem_map ) );
                current_offset += sizeof( *mem_map );

                DebugMSG( "%3d: %-25s, 0x%16llx -> 0x%16llx, %5lld, 0x%016llx",
                    entryIdx++, get_efi_mem_type_str(mem_map->type),
                    mem_map->phys_addr, mem_map->virt_addr,
                    mem_map->num_pages, mem_map->attribute );
        }

        *MemoryMapSize  = current_offset - ( uint8_t* )MemoryMap;
        *MapKey         = efi_mem_map_epoch;

        DebugMSG( "MemoryMapSize = %ld MapKey = 0x%lx", 
                  *MemoryMapSize, *MapKey );

        return EFI_SUCCESS;
}

__attribute__((ms_abi)) efi_status_t efi_hook_AllocatePool(
                        EFI_MEMORY_TYPE pool_type,
                        unsigned long  size,
                        void           **buffer )
{
        void* allocation = NULL;

        DebugMSG( "pool_type = 0x%x (%s), size = 0x%lx",
                  pool_type, get_efi_mem_type_str( pool_type ), size );

        allocation = kmalloc( size, GFP_KERNEL | GFP_DMA );
        if (allocation == NULL)
                return EFI_OUT_OF_RESOURCES;

        DebugMSG( "Allocated at 0x%px (physical addr: 0x%llx)",
                  allocation, virt_to_phys( allocation ) );

        efi_setup_11_mapping( allocation, size );
        *buffer = ( void* )virt_to_phys( allocation );

        efi_register_mem_allocation( pool_type, NUM_PAGES( size ), allocation );

        efi_print_memory_map();
        return EFI_SUCCESS;
}

__attribute__((ms_abi)) efi_status_t efi_hook_AllocatePages(
                                           EFI_ALLOCATE_TYPE     Type,
                                           EFI_MEMORY_TYPE       MemoryType,
                                           UINTN                 NumberOfPages,
                                           efi_physical_addr_t   *Memory )
{
        efi_status_t status = EFI_UNSUPPORTED;

        DebugMSG( "Num pages = %lld; Allocation type: %s; "
                  "Memory type: %s; Requested address = 0x%llx",
                   NumberOfPages,
                   get_efi_allocation_type_str( Type ),
                   get_efi_mem_type_str( MemoryType ),
                   *Memory );

        if ( MemoryType != EfiLoaderData         &&
             MemoryType != EfiConventionalMemory &&
             MemoryType != EfiLoaderCode         &&
             MemoryType != EfiRuntimeServicesData
             ) {
                DebugMSG( "Unsupproted MemoryType 0x%x", MemoryType );
                return EFI_UNSUPPORTED;
        }

        if ( Type == AllocateAddress ) {
                /* We reassign the existing physical address to a new vritual
                 * address. */
                /* TODO: We should verify that it is OK to give away this
                 * address. As of now we are taking a leap of faith that giving
                 * away the requested physical address will cause no harm. */
                void* allocation =
                      memremap( *Memory, NumberOfPages*PAGE_SIZE, MEMREMAP_WB );
                DebugMSG( "Allocated %px --> 0x%llx", allocation,
                          virt_to_phys( allocation) );

                efi_setup_11_mapping( allocation, NumberOfPages * PAGE_SIZE );
                efi_register_mem_allocation( MemoryType,
                                             NumberOfPages,
                                             allocation );

                efi_print_memory_map();
                return EFI_SUCCESS;
        }
        else if ( Type == AllocateAnyPages ) {
                void* phys_allocation = 0;

                DebugMSG( "Calling efi_hook_AllocatePool" );
                status = efi_hook_AllocatePool( MemoryType,
                                                NumberOfPages * PAGE_SIZE,
                                                &phys_allocation);

                *Memory = ( efi_physical_addr_t )phys_allocation;

                /* efi_print_memory_map(); */
                return status;
        }

        DebugMSG( "FAIL! Unknown Type" );
        return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_FreePool(void* buff)
{
         DebugMSG( "buff @ %px; TODO: implement bookkeeping", buff );

         /* TODO: We need to do some book keeping for the sake of MemoryMap */

         /* Since we performed 11 mapping, we can't just kfree memory. We
          * therefore just ignore the call for now */

         return EFI_SUCCESS;
}

__attribute__((ms_abi)) efi_status_t efi_hook_CreateEvent(void)
{
         DebugMSG( "BOOT SERVICE #7 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_SetTimer(void)
{
         DebugMSG( "BOOT SERVICE #8 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_WaitForEvent(void)
{
         DebugMSG( "BOOT SERVICE #9 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_SignalEvent(void)
{
         DebugMSG( "BOOT SERVICE #10 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_CloseEvent(void)
{
         DebugMSG( "BOOT SERVICE #11 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_CheckEvent(void)
{
         DebugMSG( "BOOT SERVICE #12 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_InstallProtocolInterface(void)
{
         DebugMSG( "BOOT SERVICE #13 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_ReinstallProtocolInterface(void)
{
         DebugMSG( "BOOT SERVICE #14 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_UninstallProtocolInterface(void)
{
         DebugMSG( "BOOT SERVICE #15 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_HandleProtocol( void* handle,
                                                              EFI_GUID* guid,
                                                              void** interface )
{
        const char* protocolName = GetGuidName( guid );
        DebugMSG( "handle = 0x%px guid = %s: %s",
                   handle, protocolName, get_GUID_str( guid ) );

        if (handle == GRAPHICS_HANDLE) {
                /* When we get the GRAPHICS_HANDLE we may get different types
                 * protocols. However, we don't support
                 * gEfiEdidActiveProtocolGuid */
                if (strcmp (protocolName, "gEfiEdidActiveProtocolGuid") == 0) {
                        DebugMSG( "Handle belongs to graphics, but received "
                                  "incorrect protocol" );
                        return EFI_UNSUPPORTED;
                }

                return efi_handle_protocol_graphics ( interface );
        }
        if (strcmp (protocolName, "gEfiLoadedImageProtocolGuid") == 0) {
                return efi_handle_protocol_LoadedImage( handle, interface );
        }
        if (strcmp (protocolName, "gEfiDevicePathProtocolGuid") == 0) {
                return efi_handle_protocol_DevicePath( handle, interface );
        }
        if (strcmp (protocolName, "gEfiBlockIoProtocolGuid") == 0) {
                return efi_handle_protocol_BlockIO( handle, interface );
        }

        DebugMSG( "Unsuppurted protocol requested." );
        return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_Reserved(void)
{
         DebugMSG( "BOOT SERVICE #17 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_RegisterProtocolNotify(void)
{
         DebugMSG( "BOOT SERVICE #18 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_LocateHandle(
                                        int        SearchType,
                                        EFI_GUID   *Protocol,
                                        VOID       *SearchKey,
                                        UINTN      *BufferSize,
                                        EFI_HANDLE *Buffer)

{
        int i;
        const char* protocol_name = GetGuidName( Protocol );
        DebugMSG( "SearchType = %d, protocol = %s (%s), BufferSize = %lld "
                  "Buffer @ %px",
                  SearchType, protocol_name,
                  get_GUID_str( Protocol ), *BufferSize, Buffer );

        if (strcmp (protocol_name, "gEfiBlockIoProtocolGuid") == 0 ) {
                /* TODO: We should analize the real hard drive and return
                 * handles according to the actual partitions that exist on it.
                 * the current "devices" array is hard coding of the partitions
                 * which exist in our disk image. */
                if (*BufferSize < sizeof( EFI_HANDLE ) * NUM_DEVICES) {
                       *BufferSize = sizeof( EFI_HANDLE ) * NUM_DEVICES;
                       return EFI_BUFFER_TOO_SMALL;
                }

                *BufferSize = sizeof( EFI_HANDLE ) * NUM_DEVICES;

                for (i = 0; i < NUM_DEVICES; i++) {
                       Buffer[i] = devices[i].handle;
                       DebugMSG( "Adding devices[%d].handle = %px", i, Buffer[i] );
                }

                return EFI_SUCCESS;
        }
        // else
        if (strcmp (protocol_name, "gEfiGraphicsOutputProtocolGuid") == 0 ) {
                if (*BufferSize < sizeof( EFI_HANDLE )) {
                       *BufferSize = sizeof( EFI_HANDLE );
                       return EFI_BUFFER_TOO_SMALL;
                }

                *BufferSize = sizeof( EFI_HANDLE );
                Buffer[0] = GRAPHICS_HANDLE;
                DebugMSG( "Graphics handle = %px", Buffer[0] );

                return EFI_SUCCESS;
        }

        DebugMSG( "Unsupported protocol" );
        return EFI_NOT_FOUND;
}

__attribute__((ms_abi)) efi_status_t efi_hook_LocateDevicePath(void)
{
         DebugMSG( "BOOT SERVICE #20 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_InstallConfigurationTable(void)
{
         DebugMSG( "BOOT SERVICE #21 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_LoadImage(void)
{
         DebugMSG( "BOOT SERVICE #22 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_StartImage(void)
{
         DebugMSG( "BOOT SERVICE #23 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_Exit(void)
{
         DebugMSG( "BOOT SERVICE #24 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_UnloadImage(void)
{
         DebugMSG( "BOOT SERVICE #25 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_ExitBootServices(void)
{
         /* TODO: When this ExitBootServices is called we should gracefully shut
          * down linux. This shoudl be done similarly to how kexec shuts down
          * the existing kernel.
          */
         DebugMSG( "Returning SUCCESS" );
         return EFI_SUCCESS;
}

__attribute__((ms_abi)) efi_status_t efi_hook_GetNextMonotonicCount(void)
{
         DebugMSG( "BOOT SERVICE #27 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_Stall(void)
{
         DebugMSG( "Ignoring call" );

         return EFI_SUCCESS;
}

__attribute__((ms_abi)) efi_status_t efi_hook_SetWatchdogTimer( UINTN    Timeout,
                                                                UINT64   WatchdogCode,
                                                                UINTN    DataSize,
                                                                CHAR16   *WatchdogData )
{
        DebugMSG( "Timeout = %lld, WatchdogCode = 0x%llx, DataSize = %lld",
                  Timeout, WatchdogCode, DataSize );

        /* It's Ok to ignore this call. See
         * https://uefi.org/sites/default/files/resources/UEFI%20Spec%202_6.pdf
         * From the UEFI spec version 2.6 January, 2016:
         * The SetWatchdogTimer() function sets the system’s watchdog timer.
         * If the watchdog timer expires, the event is logged by the firmware.
         * The system may then either reset with the Runtime Service
         * ResetSystem(), or perform a platform specific action that must
         * eventually cause the platform to be reset. The watchdog timer is
         * armed before the firmware's boot manager invokes an EFI boot option.
         * The watchdog must be set to a period of 5 minutes. The EFI Image may
         * reset or disable the watchdog timer as needed. If control is
         * returned to the firmware's boot manager, the watchdog timer must be
         * disabled. The watchdog timer is only used during boot services. On
         * successful completion of EFI_BOOT_SERVICES.ExitBootServices() the
         * watchdog timer is disabled.
         *
         * Basically, the watchdog is intended to make sure the system reboots
         * in case the loader is stuck. Observing the logs after booting Windows
         * 2019 we see that Timeout = 0, WatchdogCode = 0x0, DataSize = 0.
         */
        return EFI_SUCCESS;
}

__attribute__((ms_abi)) efi_status_t efi_hook_ConnectController(void)
{
         DebugMSG( "BOOT SERVICE #30 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_DisconnectController(void)
{
         DebugMSG( "BOOT SERVICE #31 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_OpenProtocol( EFI_HANDLE  UserHandle,
                                                            EFI_GUID    *Protocol,
                                                            VOID        **Interface,
                                                            EFI_HANDLE  ImageHandle,
                                                            EFI_HANDLE  ControllerHandle,
                                                            UINT32      Attributes )

{
        const char* protocolName = GetGuidName( Protocol );
        DebugMSG( "handle = 0x%px guid = %s: %s",
                   UserHandle, protocolName, get_GUID_str( Protocol ) );

        if (strcmp (protocolName, "gEfiSimpleTextInputExProtocolGuid") == 0) {
                return efi_handle_protocol_SimpleTextInputExProtocol(
                                                        UserHandle, Interface );
        }

        DebugMSG( "Deferring to HandleProtocol" );
        return efi_hook_HandleProtocol( UserHandle, Protocol, Interface);
}

__attribute__((ms_abi)) efi_status_t efi_hook_CloseProtocol(
                                                EFI_HANDLE UserHandle,
                                                EFI_GUID   *Protocol,
                                                EFI_HANDLE AgentHandle,
                                                EFI_HANDLE ControllerHandle )
{
         DebugMSG( "UserHandle: %px, AgentHandle: %px, ControllerHandle: %px "
                   "protocol = %s (%s)",
                   UserHandle, AgentHandle, ControllerHandle,
                   GetGuidName( Protocol ), get_GUID_str( Protocol ));

         return EFI_SUCCESS;
}

__attribute__((ms_abi)) efi_status_t efi_hook_OpenProtocolInformation(void)
{
         DebugMSG( "BOOT SERVICE #34 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_ProtocolsPerHandle(void)
{
         DebugMSG( "BOOT SERVICE #35 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_LocateHandleBuffer(void)
{
         DebugMSG( "BOOT SERVICE #36 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_LocateProtocol(void)
{
         DebugMSG( "BOOT SERVICE #37 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_InstallMultipleProtocolInterfaces(void)
{
         DebugMSG( "BOOT SERVICE #38 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_UninstallMultipleProtocolInterfaces(void)
{
         DebugMSG( "BOOT SERVICE #39 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_CalculateCrc32(void)
{
         DebugMSG( "BOOT SERVICE #40 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_CopyMem(void)
{
         DebugMSG( "BOOT SERVICE #41 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_SetMem(void)
{
         DebugMSG( "BOOT SERVICE #42 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_hook_CreateEventEx(void)
{
         DebugMSG( "BOOT SERVICE #43 called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_conout_hook_Reset(void)
{
         DebugMSG( "ConOut was called" );

         return EFI_UNSUPPORTED;
}

void wchar_to_ascii( char *dst_ascii, size_t len, char* src_wchar)
{
        /* src_wcharis CHAR16. We convert it to char* by skipping every
         * 2nd char */
        unsigned int currIdx = 0;
        char c;

        while (currIdx < len)
        {
                c = src_wchar[currIdx*2];
                if (c == 0)
                        break;

                dst_ascii[currIdx++] = c;
        }
}

__attribute__((ms_abi)) efi_status_t efi_conout_hook_OutputString(void* this,
                                                                  char* str )
{
        char str_as_ascii[1024] = {0};
        wchar_to_ascii( str_as_ascii, sizeof( str_as_ascii ), str );

        DebugMSG( "output: %s", str_as_ascii );

        return EFI_SUCCESS;
}

__attribute__((ms_abi)) efi_status_t efi_conout_hook_TestString(void)
{
         DebugMSG( "ConOut was called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_conout_hook_QueryMode(void)
{
         DebugMSG( "ConOut was called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_conout_hook_SetMode(void)
{
         DebugMSG( "ConOut was called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_conout_hook_SetAttribute(void)
{
         DebugMSG( "ConOut was called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_conout_hook_ClearScreen(void)
{
         DebugMSG( "ConOut was called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_conout_hook_SetCursorPosition(void)
{
         DebugMSG( "ConOut was called" );

         return EFI_UNSUPPORTED;
}

__attribute__((ms_abi)) efi_status_t efi_conout_hook_EnableCursor(void)
{
         DebugMSG( "ConOut was called" );

         return EFI_UNSUPPORTED;
}

EFI_SIMPLE_TEXT_OUTPUT_MODE efi_conout_mode = {
        .MaxMode       = 3,
        .Mode          = 0,
        .Attribute     = 15,
        .CursorColumn  = 0,
        .CursorRow     = 0,
        .CursorVisible = 0
};

EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL con_out = {
        .Reset             = efi_conout_hook_Reset,
        .OutputString      = efi_conout_hook_OutputString,
        .TestString        = efi_conout_hook_TestString,
        .QueryMode         = efi_conout_hook_QueryMode,
        .SetMode           = efi_conout_hook_SetMode,
        .SetAttribute      = efi_conout_hook_SetAttribute,
        .ClearScreen       = efi_conout_hook_ClearScreen,
        .SetCursorPosition = efi_conout_hook_SetCursorPosition,
        .EnableCursor      = efi_conout_hook_EnableCursor,
        .Mode              = &efi_conout_mode
};

void* efi_boot_service_hooks[44] = {0};

void initialize_efi_boot_service_hooks(void)
{
        efi_boot_service_hooks[0] = efi_hook_RaiseTPL;
        efi_boot_service_hooks[1] = efi_hook_RestoreTPL;
        efi_boot_service_hooks[2] = efi_hook_AllocatePages;
        efi_boot_service_hooks[3] = efi_hook_FreePages;
        efi_boot_service_hooks[4] = efi_hook_GetMemoryMap;
        efi_boot_service_hooks[5] = efi_hook_AllocatePool;
        efi_boot_service_hooks[6] = efi_hook_FreePool;
        efi_boot_service_hooks[7] = efi_hook_CreateEvent;
        efi_boot_service_hooks[8] = efi_hook_SetTimer;
        efi_boot_service_hooks[9] = efi_hook_WaitForEvent;
        efi_boot_service_hooks[10] = efi_hook_SignalEvent;
        efi_boot_service_hooks[11] = efi_hook_CloseEvent;
        efi_boot_service_hooks[12] = efi_hook_CheckEvent;
        efi_boot_service_hooks[13] = efi_hook_InstallProtocolInterface;
        efi_boot_service_hooks[14] = efi_hook_ReinstallProtocolInterface;
        efi_boot_service_hooks[15] = efi_hook_UninstallProtocolInterface;
        efi_boot_service_hooks[16] = efi_hook_HandleProtocol;
        efi_boot_service_hooks[17] = efi_hook_Reserved;
        efi_boot_service_hooks[18] = efi_hook_RegisterProtocolNotify;
        efi_boot_service_hooks[19] = efi_hook_LocateHandle;
        efi_boot_service_hooks[20] = efi_hook_LocateDevicePath;
        efi_boot_service_hooks[21] = efi_hook_InstallConfigurationTable;
        efi_boot_service_hooks[22] = efi_hook_LoadImage;
        efi_boot_service_hooks[23] = efi_hook_StartImage;
        efi_boot_service_hooks[24] = efi_hook_Exit;
        efi_boot_service_hooks[25] = efi_hook_UnloadImage;
        efi_boot_service_hooks[26] = efi_hook_ExitBootServices;
        efi_boot_service_hooks[27] = efi_hook_GetNextMonotonicCount;
        efi_boot_service_hooks[28] = efi_hook_Stall;
        efi_boot_service_hooks[29] = efi_hook_SetWatchdogTimer;
        efi_boot_service_hooks[30] = efi_hook_ConnectController;
        efi_boot_service_hooks[31] = efi_hook_DisconnectController;
        efi_boot_service_hooks[32] = efi_hook_OpenProtocol;
        efi_boot_service_hooks[33] = efi_hook_CloseProtocol;
        efi_boot_service_hooks[34] = efi_hook_OpenProtocolInformation;
        efi_boot_service_hooks[35] = efi_hook_ProtocolsPerHandle;
        efi_boot_service_hooks[36] = efi_hook_LocateHandleBuffer;
        efi_boot_service_hooks[37] = efi_hook_LocateProtocol;
        efi_boot_service_hooks[38] = efi_hook_InstallMultipleProtocolInterfaces;
        efi_boot_service_hooks[39] = efi_hook_UninstallMultipleProtocolInterfaces;
        efi_boot_service_hooks[40] = efi_hook_CalculateCrc32;
        efi_boot_service_hooks[41] = efi_hook_CopyMem;
        efi_boot_service_hooks[42] = efi_hook_SetMem;
        efi_boot_service_hooks[43] = efi_hook_CreateEventEx;
}

char memory_type_name[][20] = {
	"Reserved",
	"Loader Code",
	"Loader Data",
	"Boot Code",
	"Boot Data",
	"Runtime Code",
	"Runtime Data",
	"Conventional Memory",
	"Unusable Memory",
	"ACPI Reclaim Memory",
	"ACPI Memory NVS",
	"Memory Mapped I/O",
	"MMIO Port Space",
	"PAL Code"
};

char e820_types[][32] = {
        "val=0",
        "E820_RAM",
        "E8E820_RESERVED",
        "E8E820_ACPI",
        "E8E820_NVS",
        "E8E820_UNUSABLE",
        "val=6",
        "E8E820_PMEM",
        "val=8",
        "val=9",
        "val=10",
        "val=11",
        "E820_PRAM"
};

void print_e820_memmap(void)
{
        struct e820_table* map = e820_table;
        int i;

        for (i = 0; i < map->nr_entries; i++) {
                struct e820_entry *entry = &map->entries[i];
                char *type_str = "<unknown>";
                if (entry->type < ARRAY_SIZE(e820_types))
                        type_str = e820_types[entry->type];
                if (entry->type == E820_TYPE_RESERVED_KERN )
                        type_str = "E820_RESERVED_KERN";

                DebugMSG( "%2d: 0x%016llx-0x%016llx  size: 0x%-12llx "
                          "(%-6lld pages) type=%d: %s",
                          i,
                          entry->addr,
                          entry->addr + entry->size - 1,
                          entry->size,
                          NUM_PAGES( entry->size ),
                          entry->type,
                          type_str );
        }
}

/* Locate the entry id in the e820 mapping that matches a physical address. */
int get_efi_entry_by_addr(u64 addr)
{
        struct e820_table* map = e820_table;
        int i;

        for (i = 0; i < map->nr_entries; i++) {
                struct e820_entry *entry = &map->entries[i];

                if (addr >= entry->addr && addr < entry->addr + entry->size)
                        return i;
        }

        return -1;

}

/* Receive addr, a physical address which resides in one of the e820 mappings,
 * locate the matching region in the e820 mapping, and create a virtual address
 * space matching exactly the physcial region (1:1 mapping). */
void efi_remap_area( u64 addr, EFI_MEMORY_TYPE type )
{
        struct e820_table* map   = e820_table;
        int entry_id             = get_efi_entry_by_addr( addr );
        struct e820_entry *entry = &map->entries[entry_id];
        unsigned long start      = ALIGN_DOWN( entry->addr ,PAGE_SIZE);
        unsigned long end        = ALIGN( entry->addr + entry->size, PAGE_SIZE);
        unsigned long size       = end - start;

        DebugMSG( "addr = 0x%llx, entry_id = %d entry->addr = 0x%llx",
                  addr, entry_id, entry->addr );

        efi_register_phys_mem_allocation( type, NUM_PAGES( size ), start );
        efi_setup_11_mapping_physical_addr( start, end );
}

void efi_remap_phys_page( u64 addr )
{
        unsigned long start = ALIGN_DOWN( addr, PAGE_SIZE );
        unsigned long end   = ALIGN( addr, PAGE_SIZE );

        DebugMSG( "Remapping addr 0x%llx", addr );

        efi_setup_11_mapping_physical_addr( start, end );
}

efi_config_table_t efi_config_table[2] = {0};

struct DESCRIPTION_HEADER
{
    UINT32 Signature;
    UINT32 Length;
    UCHAR Revision;
    UCHAR Checksum;
    UCHAR OEMID[6];
    UCHAR OEMTableID[8];
    UINT32 OEMRevision;
    UCHAR CreatorID[4];
    UINT32 CreatorRev;
} __attribute__((packed));

struct  RSDP
{
    UINT64 Signature;
    UCHAR Checksum;
    UCHAR OEMID[6];
    UCHAR Revision;
    UINT32 RsdtAddress;
    UINT32 Length;
    UINT64 XsdtAddress;
    UCHAR XChecksum;
    UCHAR Reserved[3];
} __attribute__((packed));

struct RSDT
{
    struct DESCRIPTION_HEADER Header;
    UINT32 Tables[];
}  __attribute__((packed));

struct BGRT_TABLE
{
    struct DESCRIPTION_HEADER Header;
    UINT16 Version;
    UCHAR Status;
    UCHAR ImageType;
    UINT64 LogoAddress;
    UINT32 OffsetX;
    UINT32 OffsetY;
} __attribute__((packed)) ;

#define BGRT_SIGNATURE  0x54524742              // "BGRT"
struct BGRT_TABLE* efi_find_bgrt(void)
{
        struct RSDP *rsdp       = NULL;
        struct RSDT *rsdt       = NULL;
        struct BGRT_TABLE* bgrt = NULL;
        int num_entries;
        int i;

        rsdp = (void*)efi.acpi20;
        rsdt = (struct RSDT*)((u64)rsdp->RsdtAddress);
        num_entries = (rsdt->Header.Length -
                       sizeof(struct DESCRIPTION_HEADER))/sizeof(UINT32);

        for (i=0; i < num_entries; i++) {
                u64 table_addr = (u64)rsdt->Tables[i];
                u32 signature = *(u32*)table_addr;

                DebugMSG( "Table at 0x%llx signature = 0x%x",
                          table_addr, signature );

                if (signature == BGRT_SIGNATURE)
                        bgrt = (struct BGRT_TABLE*)table_addr;
        }

        return bgrt;
}

/* The ACPI configuration tables may point to areas in regular RAM. We want to
 * create 1:1 mappings for these locataions so we won't get a page fault when
 * Windows loader accesses them. */
void efi_remap_ram_used_by_tables(void)
{
        struct BGRT_TABLE* bgrt = efi_find_bgrt();

        DebugMSG( "Found BGRT at %px", bgrt );

        efi_remap_phys_page( bgrt->LogoAddress );
}

void efi_setup_configuration_tables( efi_system_table_t *systab )
{
        efi_guid_t smbios_guid = SMBIOS_TABLE_GUID;
        efi_guid_t acpi20_guid = ACPI_20_TABLE_GUID;
        int table_id           = 0;

        print_e820_memmap();
        DebugMSG( "############### acpi20 @ 0x%lx (entry %d)",
                  efi.acpi20, get_efi_entry_by_addr( efi.acpi20 ) );
        DebugMSG( "############### acpi@ 0x%lx (entry %d)",
                  efi.acpi, get_efi_entry_by_addr( efi.acpi ) );
        DebugMSG( "############### SMBIOS @ 0x%lx (entry %d)",
                  efi.smbios, get_efi_entry_by_addr( efi.smbios ) );

        /* We need to make sure the physical address pointed by the
         * configuration table is addressable also via virtual addressing. We
         * solve this by creating a 1:1 mapping for the entire regions. */
        efi_remap_area( efi.acpi20, EfiReservedMemoryType );

        /* SMBIOS is on the same memory region as Runtime Services. */
        efi_remap_area( efi.smbios, EfiRuntimeServicesCode );

        memcpy( &efi_config_table[table_id].guid, &acpi20_guid,
                sizeof(acpi20_guid) );
        efi_config_table[table_id++].table = efi.acpi20;

        memcpy( &efi_config_table[table_id].guid, &smbios_guid,
                sizeof(smbios_guid) );
        efi_config_table[table_id++].table = efi.smbios;

        systab->nr_tables = table_id;
        systab->tables    = (unsigned long)efi_map_11_and_register_allocation(
                                                &efi_config_table,
                                                sizeof(efi_config_table));

        efi_remap_ram_used_by_tables();
}

CHAR16 fw_vendor_wchar[256];
char *fw_vendor = "U-ROOT_Fake_Firmware";

static void hook_boot_services( efi_system_table_t *systab )

{
        efi_boot_services_t *boot_services       = &linux_bootservices;
        void                **bootServiceFuncPtr = NULL;
        int                 boot_service_idx     = 0;
        uint64_t            top_of_bootservices;

        uint64_t            *systab_blob         = (uint64_t *)systab;
        uint64_t            marker               = 0xdeadbeefcafeba00;

        /*
         * Fill boot services table with known incrementing  values
         * This will help debugging when we see RIP or other registers
         * containing theses fixed values */
        while ( (uint8_t*)systab_blob < (uint8_t*)systab + sizeof( *systab ) ) {
                *systab_blob = marker++;
                systab_blob += 1;
        }

        efi_set_wstring_from_ascii( fw_vendor_wchar, fw_vendor,
                                    sizeof(fw_vendor_wchar) );

        systab->fw_vendor      =
                        (unsigned long)efi_map_11_and_register_allocation(
                                                fw_vendor_wchar,
                                                sizeof(fw_vendor_wchar));
        systab->con_in_handle  = CON_IN_HANDLE;
        systab->con_in         = 0xdeadbeefcafe0001;
        systab->con_out_handle = 0xdeadbeefcafebabe;
        systab->con_out        =
                        (unsigned long)efi_map_11_and_register_allocation(
                                                &con_out,
                                                sizeof(con_out) );
        systab->stderr_handle  = 0xdeadbeefcafe0003;
        systab->stderr         = 0xdeadbeefcafe0004;
        systab->runtime        = (void*)efi.runtime;

        DebugMSG( "systab->runtime->set_virtual_address_map @ %px",
                  systab->runtime->set_virtual_address_map );
        efi_setup_configuration_tables(systab);
        efi_print_memory_map();


        /* We will fill boot_services with actual function pointer, but this is
         * a precaution in case we missed a function pointer in our setup. */
        memset(boot_services, 0x43, sizeof( *boot_services ) );

        initialize_efi_boot_service_hooks();
        bootServiceFuncPtr  = &boot_services->raise_tpl; /* This is the first service */
        top_of_bootservices =
                (uint64_t)boot_services + sizeof( efi_boot_services_t );

        /* Now assign the function poointers: */
        while( (uint64_t)bootServiceFuncPtr < top_of_bootservices ) {
                *bootServiceFuncPtr = efi_boot_service_hooks[boot_service_idx];
                bootServiceFuncPtr += 1;
                boot_service_idx   += 1;
        }

        systab->boottime = boot_services;
}

void efi_register_ram_as_available(void)
{
        /* We assume the last entry in the e820 map is usable RAM. Pieces of
         * this memory are used by Linux, but we declare the entire region as
         * usable memory so Windows loader will not fail wtih 0xC000009A:
         * "STATUS_INSUFFICIENT_RESOURCES" */

        u32 num_regions          = e820_table->nr_entries;
        struct e820_entry *entry = &e820_table->entries[num_regions-1];

        DebugMSG( "Marking RAM as available" );
        efi_register_phys_mem_allocation( EfiConventionalMemory,
                                          NUM_PAGES( entry->size ),
                                          entry->addr );
}

typedef uint64_t (*EFI_APP_ENTRY)( void* imageHandle, void* systemTable  )
        __attribute__((ms_abi));

/* Different parts of Windows loader will need to believe they have physical
 * addresses of various structures. We do this by creating a virtual address
 * which is identical to the physical address of the structure. */
void* efi_map_11_and_register_allocation(void* virt_kernel_addr, size_t size)
{
        /* TODO: check reurn values for errors */

        unsigned long physical_address = virt_to_phys(virt_kernel_addr);

        unsigned long start = ALIGN_DOWN(physical_address, PAGE_SIZE);
        unsigned long end   = ALIGN(physical_address + size, PAGE_SIZE);

        /* Create the mapping. efi_setup_11_mapping will handle the case that
         * the mapping already exists. */
        efi_setup_11_mapping(virt_kernel_addr, size);

        /* We need to make sure that Windows loader maps this addresses in its
         * own memory pages structures. We make sure of that by having these
         * areas apear returned by GetMemoryMap as EfiBootServicesData, */
        /* TODO: Handle the case that the mapping is already registered. Right
         * now the mapping will be added, even if it already exists. */
        efi_register_phys_mem_allocation(
                EfiBootServicesData,
                NUM_PAGES(end - start),
                start);

        return (void*)physical_address;
}

void efi_mark_reserved_areas(void)
{
        struct e820_table* map = e820_table;
        int i;

        DebugMSG ("Marking reserved memory areas" );

        for (i = 0; i < map->nr_entries; i++) {
                struct e820_entry *entry   = &map->entries[i];
                EFI_MEMORY_TYPE   efi_type = EfiReservedMemoryType;

                /* The reserved areas also contain the code for runtime
                 * services. We want to mark them as such so that windows loader
                 * will map them into memory. */

                if (entry->type == E820_TYPE_RESERVED)
                        efi_type = EfiRuntimeServicesCode;
                else if (entry->type == E820_TYPE_ACPI)
                        efi_type = EfiACPIReclaimMemory;
                else if (entry->type == E820_TYPE_NVS)
                        efi_type = EfiACPIMemoryNVS;
                else if (entry->type == E820_TYPE_UNUSABLE)
                        efi_type = EfiUnusableMemory;
                else
                        continue;

                /* For runtime services code, we want these addresses to be
                 * accessible during bootloading. We therefore need to remap
                 * them into 1:1 virt-to-pys memory */
                if (efi_type == EfiRuntimeServicesCode)
                        efi_remap_area( entry->addr, EfiRuntimeServicesCode );
                else
                        efi_register_phys_mem_allocation( efi_type,
                                                          NUM_PAGES( entry->size ),
                                                          entry->addr );
        }

}

void launch_efi_app(EFI_APP_ENTRY efiApp, efi_system_table_t *systab)
{
        /* Fake handle */
        EFI_HANDLE          ImageHandle     = (void*)0xDEADBEEF;
        efi_physical_addr_t pool            = 0x100000;
        UINTN               pool_pages      = 200;
        efi_system_table_t* remapped_systab = NULL;

        /* We need to create a large pool of EfiConventionalMemory, so Windows
         * loader will believe there is sufficient memory. Otherwise it won't
         * even call the EFI AllocatePages function and fail with error code
         * 0xC0000017 (STATUS_NO_MEMORY) */
        efi_hook_AllocatePages( AllocateAnyPages, EfiConventionalMemory,
                                pool_pages, &pool );

        /* The system table must be accessible via physical addressing. We
         * therefore create 1:1 mapping of the location of it. */
        remapped_systab =
                (efi_system_table_t *)efi_map_11_and_register_allocation(
                                                        systab,
                                                        sizeof( *systab ));

        efiApp( ImageHandle, remapped_systab );
}

void efi_remove_NX_bit( unsigned long addr )
{
        struct mm_struct *mm  = current->mm;
	pgd_t *pgd;
	unsigned long *p4d;

        /* We actually have 4 levels of memory, so pgd and p4d are the same */
	pgd = pgd_offset(mm, addr);
	p4d = (unsigned long*)p4d_offset(pgd, addr);
        DebugMSG( "pgd = 0x%lx", pgd->pgd );
        DebugMSG( "p4d = 0x%lx", *p4d );
        pgd->pgd &= ~_PAGE_NX;
        DebugMSG( "pgd = 0x%lx", pgd->pgd );
        DebugMSG( "p4d = 0x%lx", *p4d );

        /* TODO: flush TLB !!!! */
}

void kimage_run_pe(struct kimage *image)
{
        EFI_APP_ENTRY efiApp = (EFI_APP_ENTRY)image->raw_image_start;

        /* This is a hack to remove the NX bit from P4D. Otherwise we will get a
         * fault when fetching the very first instruction at the entry_point.
         * While it seems ill advised to turn off the NX bit, recall that we are
         * actually loading arbitrary code (Windows loader) and executing it in
         * kernel mode. That code is then taking over the machine. */
        efi_remove_NX_bit( (unsigned long)image->raw_image_start );

        /* Print the beginning of the entry point. You can compare this to the
         * objdump output of the EFI app you're running. */
        DumpBuffer( "Entry point:", (uint8_t*) image->raw_image_start, 64 );


        efi_register_ram_as_available();
        efi_mark_reserved_areas();

        hook_boot_services( &fake_systab );
        efiApp = (EFI_APP_ENTRY)image->raw_image_start;
        launch_efi_app( efiApp, &fake_systab );
}

static int do_kexec_load(unsigned long entry, unsigned long nr_segments,
		struct kexec_segment __user *segments, unsigned long flags)
{
	struct kimage **dest_image, *image;
	unsigned long i;
	int ret;

	if (flags & KEXEC_ON_CRASH) {
		dest_image = &kexec_crash_image;
		if (kexec_crash_image)
			arch_kexec_unprotect_crashkres();
	} else {
		dest_image = &kexec_image;
	}

	if (nr_segments == 0) {
		/* Uninstall image */
		kimage_free(xchg(dest_image, NULL));
		return 0;
	}
	if (flags & KEXEC_ON_CRASH) {
		/*
		 * Loading another kernel to switch to if this one
		 * crashes.  Free any current crash dump kernel before
		 * we corrupt it.
		 */
		kimage_free(xchg(&kexec_crash_image, NULL));
	}

	ret = kimage_alloc_init(&image, entry, nr_segments, segments, flags);
	if (ret)
		return ret;

        if (flags & KEXEC_RUN_PE) {
                kimage_load_pe(image, nr_segments);
                kimage_run_pe(image);

                goto out;
        }

	if (flags & KEXEC_PRESERVE_CONTEXT)
		image->preserve_context = 1;

	ret = machine_kexec_prepare(image);
	if (ret)
		goto out;

	/*
	 * Some architecture(like S390) may touch the crash memory before
	 * machine_kexec_prepare(), we must copy vmcoreinfo data after it.
	 */
	ret = kimage_crash_copy_vmcoreinfo(image);
	if (ret)
		goto out;

	for (i = 0; i < nr_segments; i++) {
		ret = kimage_load_segment(image, &image->segment[i]);
		if (ret)
			goto out;
	}

	kimage_terminate(image);

	/* Install the new kernel and uninstall the old */
	image = xchg(dest_image, image);

out:
	if ((flags & KEXEC_ON_CRASH) && kexec_crash_image)
		arch_kexec_protect_crashkres();

	kimage_free(image);
	return ret;
}

/*
 * Exec Kernel system call: for obvious reasons only root may call it.
 *
 * This call breaks up into three pieces.
 * - A generic part which loads the new kernel from the current
 *   address space, and very carefully places the data in the
 *   allocated pages.
 *
 * - A generic part that interacts with the kernel and tells all of
 *   the devices to shut down.  Preventing on-going dmas, and placing
 *   the devices in a consistent state so a later kernel can
 *   reinitialize them.
 *
 * - A machine specific part that includes the syscall number
 *   and then copies the image to it's final destination.  And
 *   jumps into the image at entry.
 *
 * kexec does not sync, or unmount filesystems so if you need
 * that to happen you need to do that yourself.
 */

static inline int kexec_load_check(unsigned long nr_segments,
				   unsigned long flags)
{
	int result;

	/* We only trust the superuser with rebooting the system. */
	if (!capable(CAP_SYS_BOOT) || kexec_load_disabled)
		return -EPERM;

	/* Permit LSMs and IMA to fail the kexec */
	result = security_kernel_load_data(LOADING_KEXEC_IMAGE);
	if (result < 0)
		return result;

	/*
	 * Verify we have a legal set of flags
	 * This leaves us room for future extensions.
	 */
	if ((flags & KEXEC_FLAGS) != (flags & ~KEXEC_ARCH_MASK))
		return -EINVAL;

	/* Put an artificial cap on the number
	 * of segments passed to kexec_load.
	 */
	if (nr_segments > KEXEC_SEGMENT_MAX)
		return -EINVAL;

	return 0;
}

SYSCALL_DEFINE4(kexec_load, unsigned long, entry, unsigned long, nr_segments,
		struct kexec_segment __user *, segments, unsigned long, flags)
{
	int result;

	result = kexec_load_check(nr_segments, flags);
	if (result)
		return result;

	/* Verify we are on the appropriate architecture */
	if (((flags & KEXEC_ARCH_MASK) != KEXEC_ARCH) &&
		((flags & KEXEC_ARCH_MASK) != KEXEC_ARCH_DEFAULT))
		return -EINVAL;

	/* Because we write directly to the reserved memory
	 * region when loading crash kernels we need a mutex here to
	 * prevent multiple crash  kernels from attempting to load
	 * simultaneously, and to prevent a crash kernel from loading
	 * over the top of a in use crash kernel.
	 *
	 * KISS: always take the mutex.
	 */
	if (!mutex_trylock(&kexec_mutex))
		return -EBUSY;

	result = do_kexec_load(entry, nr_segments, segments, flags);

	mutex_unlock(&kexec_mutex);

	return result;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(kexec_load, compat_ulong_t, entry,
		       compat_ulong_t, nr_segments,
		       struct compat_kexec_segment __user *, segments,
		       compat_ulong_t, flags)
{
	struct compat_kexec_segment in;
	struct kexec_segment out, __user *ksegments;
	unsigned long i, result;

	result = kexec_load_check(nr_segments, flags);
	if (result)
		return result;

	/* Don't allow clients that don't understand the native
	 * architecture to do anything.
	 */
	if ((flags & KEXEC_ARCH_MASK) == KEXEC_ARCH_DEFAULT)
		return -EINVAL;

	ksegments = compat_alloc_user_space(nr_segments * sizeof(out));
	for (i = 0; i < nr_segments; i++) {
		result = copy_from_user(&in, &segments[i], sizeof(in));
		if (result)
			return -EFAULT;

		out.buf   = compat_ptr(in.buf);
		out.bufsz = in.bufsz;
		out.mem   = in.mem;
		out.memsz = in.memsz;

		result = copy_to_user(&ksegments[i], &out, sizeof(out));
		if (result)
			return -EFAULT;
	}

	/* Because we write directly to the reserved memory
	 * region when loading crash kernels we need a mutex here to
	 * prevent multiple crash  kernels from attempting to load
	 * simultaneously, and to prevent a crash kernel from loading
	 * over the top of a in use crash kernel.
	 *
	 * KISS: always take the mutex.
	 */
	if (!mutex_trylock(&kexec_mutex))
		return -EBUSY;

	result = do_kexec_load(entry, nr_segments, ksegments, flags);

	mutex_unlock(&kexec_mutex);

	return result;
}
#endif
