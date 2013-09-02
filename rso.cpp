/*
 *  IDA Nintendo GameCube rso Loader Module
 *  (C) Copyright 2013 Stephen Simpson
 *
 */

#include <ida.hpp>
#include <fpro.h>
#include <idp.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <srarea.hpp>
#include <fixup.hpp>
#include <entry.hpp>
#include <auto.hpp>
#include <diskio.hpp>
#include <kernwin.hpp>
#include "rso.h"

//#define DEBUG

void PatchByte(uint32_t address, unsigned char value)
{
	patch_byte((ea_t)address, (ulong)value);
}
uint32_t GetSectionAddress(uint32_t section, uint32_t offset)
{
	char buf[0x100];
	qsnprintf(buf, 0x100, ".section%u", section);
	segment_t * segm = get_segm_by_name(buf);
	if (segm)
	{
		return segm->startEA + offset;
	}
	return 0xFFFFFFFF;
}
void PatchAddress32(uint32_t section, uint32_t offset, uint32_t value)
{
	/* S + A */
	uint32_t where = GetSectionAddress(section, offset);
	patch_long(where, value);
	//PatchByte(where + 0, (value >> 24) & 0xFF);
	//PatchByte(where + 1, (value >> 16) & 0xFF);
	//PatchByte(where + 2, (value >>  8) & 0xFF);
	//PatchByte(where + 3, (value >>  0) & 0xFF);
}
void PatchAddressLO(uint32_t section, uint32_t offset, uint32_t value)
{
	/* lo(S + A) */
	uint32_t where = GetSectionAddress(section, offset);
	patch_word(where, value&0xFFFF);
	//PatchByte(where + 0, (value >> 8) & 0xFF);
	//PatchByte(where + 1, (value >> 0) & 0xFF);
}
void PatchAddressHI(uint32_t section, uint32_t offset, uint32_t value)
{
	/* hi(S + A) */
	uint32_t where = GetSectionAddress(section, offset);
	patch_word(where, (value >> 16) & 0xFFFF);
	//PatchByte(where + 0, (value >> 24) & 0xFF);
	//PatchByte(where + 1, (value >> 16) & 0xFF);
}
void PatchAddressHA(uint32_t section, uint32_t offset, uint32_t value)
{
	/* ha(S + A) */
	uint32_t where = GetSectionAddress(section, offset);
	if ((value & 0x8000) == 0x8000)
	{
		value += 0x00010000;
	}
	patch_word(where, (value >> 16) & 0xFFFF);
	//PatchByte(where + 0, (value >> 24) & 0xFF);
	//PatchByte(where + 1, (value >> 16) & 0xFF);
}
void PatchAddress24(uint32_t section, uint32_t offset, uint32_t value)
{
	/* (S + A - P) >> 2 */
	uint32_t where = GetSectionAddress(section, offset);
	value -= where;
	ulong orig = get_original_long(where);
	orig &= 0xFC000003;
	orig |= value & 0x03FFFFFC;
	PatchByte(where + 0, (orig >> 24) & 0xFF);
	PatchByte(where + 1, (orig >> 16) & 0xFF);
	PatchByte(where + 2, (orig >>  8) & 0xFF);
	PatchByte(where + 3, (orig >>  0) & 0xFF);
}

/*-----------------------------------------------------------------
 *
 *   Read the header of the (possible) rso file into memory. Swap
 *   all bytes because the file is stored as big endian.
 *
 */
int read_header(linput_t *fp, rsohdr *rhdr)
{
	int i;
	/* read in rsoheader */
	qlseek(fp, 0, SEEK_SET);
	if(qlread(fp, rhdr, sizeof(rsohdr)) != sizeof(rsohdr))
	{
#ifdef DEBUG
		msg("Nintendo Rso Loader Plugin 0.1 read_header() : 1\n");
#endif
		return(0);
	}

	/* convert header */
#if USING_RSO
	rhdr->ModuleID = swap32(rhdr->ModuleID);
#endif
	rhdr->Prev = swap32(rhdr->Prev);
	rhdr->Next = swap32(rhdr->Next);
	rhdr->SectionCount = swap32(rhdr->SectionCount);
	rhdr->SectionOffset = swap32(rhdr->SectionOffset);
	rhdr->PathOffset = swap32(rhdr->PathOffset);
	rhdr->PathLength = swap32(rhdr->PathLength);
	rhdr->Version = swap32(rhdr->Version);
	rhdr->BssSize = swap32(rhdr->BssSize);
	rhdr->RelOffset = swap32(rhdr->RelOffset);
	rhdr->ImpOffset = swap32(rhdr->ImpOffset);
	rhdr->ImpSize = swap32(rhdr->ImpSize);
	rhdr->Prolog = swap32(rhdr->Prolog);
	rhdr->Epilog = swap32(rhdr->Epilog);
	rhdr->Unresolved = swap32(rhdr->Unresolved);
#ifdef DEBUG
	msg("Prev:%X\n", rhdr->Prev);
	msg("Next:%X\n", rhdr->Next);
	msg("Section Count: %X\n", rhdr->SectionCount);
	msg("Section Offset: %X\n", rhdr->SectionOffset);
	msg("Path Offset: %X\n", rhdr->PathOffset);
	msg("Path Length: %X\n", rhdr->PathLength);
	msg("Version: %d\n", rhdr->Version);
	msg("BssSize: %08x\n", rhdr->BssSize);
	msg("RelOffset: %08x\n", rhdr->RelOffset);
	msg("ImpOffset: %08x\n", rhdr->ImpOffset);
	msg("ImpSize: %08x\n", rhdr->ImpSize);
	msg("PrologS:%d EpilogS:%d UnresolvedS:%d BssS:%d\n",
			rhdr->PrologSection,
			rhdr->EpilogSection,
			rhdr->UnresolvedSection,
			rhdr->BssSection);
	msg("Prolog:%08x Epilog:%08x Unresolved:%08x\n",
			rhdr->Prolog, rhdr->Epilog, rhdr->Unresolved);
#endif
	if (rhdr->Version >= 2)
	{
		rhdr->align = swap32(rhdr->align);
		rhdr->bssAlign = swap32(rhdr->bssAlign);
	}
	if (rhdr->Version >= 3)
	{
		rhdr->fixSize = swap32(rhdr->fixSize);
	}
	return(1);
}
int read_header_v1_extra(linput_t *fp, module_v1_extra *xtra)
{
	qlseek(fp, 0x30, SEEK_SET);
	if(qlread(fp, xtra, sizeof(module_v1_extra)) != sizeof(module_v1_extra))
	{
#ifdef DEBUG
		msg("read_header_v1_extra() : 1\n");
#endif
		return(0);
	}
	xtra->internal_table_offset = swap32(xtra->internal_table_offset);
	xtra->internal_table_length = swap32(xtra->internal_table_length);
	xtra->external_table_offset = swap32(xtra->external_table_offset);
	xtra->external_table_length = swap32(xtra->external_table_length);
	xtra->export_table_offset = swap32(xtra->export_table_offset);
	xtra->export_table_length = swap32(xtra->export_table_length);
	xtra->export_table_names = swap32(xtra->export_table_names);
	xtra->import_table_offset = swap32(xtra->import_table_offset);
	xtra->import_table_length = swap32(xtra->import_table_length);
	xtra->import_table_names = swap32(xtra->import_table_names);
#ifdef DEBUG
	msg("internal_table_offset:%08x\n", xtra->internal_table_offset);
	msg("internal_table_length:%08x\n", xtra->internal_table_length);
	msg("external_table_offset:%08x\n", xtra->external_table_offset);
	msg("external_table_length:%08x\n", xtra->external_table_length);
	msg("export_table_offset:%08x\n", xtra->export_table_offset);
	msg("export_table_length:%08x\n", xtra->export_table_length);
	msg("export_table_names:%08x\n", xtra->export_table_names);
	msg("import_table_offset:%08x\n", xtra->import_table_offset);
	msg("import_table_length:%08x\n", xtra->import_table_length);
	msg("import_table_names:%08x\n", xtra->import_table_names);
#endif
	return(1);
}

/*-----------------------------------------------------------------
 *
 *   Read the section table rso file into memory. Swap
 *   all bytes because the file is stored as big endian.
 *
 */

int read_section_table(linput_t *fp, section_entry *entries, int offset, int count)
{
	int i;
#ifdef DEBUG
	msg("read_section_table(*,*,%08x, %d);\n", offset, count);
#endif
	/* read in section table */
	qlseek(fp, offset, SEEK_SET);
	if(qlread(fp, entries, sizeof(section_entry)*count) != sizeof(section_entry)*count) return(0);

	for(i=0; i<count; i++) {
		entries[i].Offset = swap32(entries[i].Offset);
		entries[i].Length = swap32(entries[i].Length);
#ifdef DEBUG
		msg("Section Offset:%08x Length:%08x\n", entries[i].Offset, entries[i].Length);
#endif
	}
	return(1);
}

/*-----------------------------------------------------------------
 *
 *   Check if input file can be a rso file. The supposed header
 *   is checked for sanity. If so return and fill in the formatname
 *   otherwise return 0
 *
 */

int idaapi accept_file(linput_t *fp, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
	int i;

	rsohdr rhdr;
	ulong filelen, valid = 0;

	if(n) return(0);

	/* first get the lenght of the file */
	filelen = qlsize(fp);
	/* if too short for a rso header then this is no RSO */
	if (filelen < sizeof(rsohdr))
	{
#ifdef DEBUG
		msg("RSO accept_file() : 1\n");
#endif
		return(0);
	}

	/* read rso header from file */
	if (read_header(fp, &rhdr)==0)
	{
#ifdef DEBUG
		msg("RSO accept_file() : 2\n");
#endif
		return(0);
	}
  
	/* now perform some sanitychecks */
	/* rso segment offet MUST BE 0x58 (0x4C!?)*/
	if ( (rhdr.SectionOffset!=0x58) && (rhdr.SectionOffset!=0x4C) )
	{
#ifdef DEBUG
		msg("RSO accept_file() : 3\n");
		msg("SectionOffset : %X\n", rhdr.SectionOffset);
#endif
		return(0);
	}

	/* file has passed all sanity checks and might be a rso */
	qstrncpy(fileformatname, "Nintendo Rso", MAX_FILE_FORMAT_NAME);
	return(ACCEPT_FIRST | 0xD07);
}



/*-----------------------------------------------------------------
 *
 *   File was recognised as rso and user has selected it.
 *   Now load it into the database
 *
 */

void idaapi load_file(linput_t *fp, ushort /*neflag*/, const char * /*fileformatname*/)
{
	rsohdr rhdr;
	int i;
	int text;

	/* Hello here I am */
	msg("---------------------------------------\n");
	msg("Nintendo Rso Loader Plugin 0.1\n");
	msg("---------------------------------------\n");
  
	/* we need PowerPC support to do anything with rsos */
	if ( ph.id != PLFM_PPC )
		set_processor_type("PPC", SETPROC_ALL|SETPROC_FATAL);

	qlseek(fp, 0, SEEK_END);
	long filesize = qltell(fp);
	qlseek(fp, 0, SEEK_SET);
	/* read rso header into memory */
	if (read_header(fp, &rhdr)==0) qexit(1);
	module_v1_extra xtra;
	if (rhdr.Version == 1)
	{
		if (read_header_v1_extra(fp, &xtra)==0) qexit(1);
	}
  
	/* every journey has a beginning */
	inf.beginEA = inf.startIP = START;

	/* map selector 1 to 0 */
	set_selector(1, 0);

	section_entry* sections = new section_entry[rhdr.SectionCount];
	if(read_section_table(fp, sections, rhdr.SectionOffset, rhdr.SectionCount) == 0) qexit(1);
	qlseek(fp, 0, SEEK_SET);

	uint32_t seg_off = START;
	/* create all segments */
	for (i=0; i<rhdr.SectionCount; i++) {
		char buf[0x100];

		/* 0 == no segment */
		if (sections[i].Offset == 0) continue;
		if (sections[i].Length == 0) continue;

		qsnprintf(buf, 0x50, ".section%u", i);

#ifdef DEBUG
		msg("Section Offset: %08x\n", sections[i].Offset);
		msg("Section Length: %08x\n", sections[i].Length);
#endif
		
		/* add the segment */
		/* is_ephemeral_segm */
		if (sections[i].Offset & SECTION_EXEC)
		{
			//add_segm_ex(1, seg_off, seg_off+sections[i].Length, buf, "CODE", ADDSEG_OR_DIE|ADDSEG_QUIET);
			if (!add_segm(1, seg_off, seg_off+sections[i].Length, buf, "CODE")) qexit(1);
		}
		else
		{
			//if (!add_segm(1, seg_off, seg_off+sections[i].Length, buf, "DATA")) qexit(1);
			if (!add_segm(1, seg_off, seg_off+sections[i].Length, buf, "CONST")) qexit(1);
			//add_segm_ex(1, seg_off, seg_off+sections[i].Length, buf, "CONST", ADDSEG_OR_DIE|ADDSEG_QUIET);
		}

		/* set addressing to 32 bit */
		set_segm_addressing(getseg(seg_off), 1);

		/* and get the content from the file */
		file2base((linput_t*)fp, SECTION_OFF(sections[i].Offset), seg_off, seg_off+sections[i].Length, FILEREG_PATCHABLE);

		/* update the segment offset */
		seg_off += sections[i].Length;
	}

	if (rhdr.RelOffset)
	{
		uint32_t current_section = 0;
		uint32_t current_offset  = 0;
		long rel_to_do = filesize - rhdr.RelOffset;
		rel_to_do /= sizeof(rel_t);
		rel_t * rel = new rel_t [rel_to_do];
		qlseek(fp, rhdr.RelOffset, SEEK_SET);
		if (qlread(fp, rel, sizeof(rel_t)*rel_to_do) == (sizeof(rel_t)*rel_to_do))
		{
			for (uint32_t ctr = 0; ctr < rel_to_do; ctr++)
			{
				rel[ctr].offset = swap16(rel[ctr].offset);
				rel[ctr].addend = swap32(rel[ctr].addend);
#ifdef DEBUG
				//if (rel[ctr].type != 6 && rel[ctr].type != 4 && rel[ctr].type != 1 && rel[ctr].type != 10)
				//{
					msg("REL %06d offset:%04x type:%03d section:%d addend:%08x (%s)\n",
							ctr,
							rel[ctr].offset, rel[ctr].type, rel[ctr].section, rel[ctr].addend,
							(rel[ctr].type <= 11) ? rel_names[rel[ctr].type] : "UNK" );
				//}
#endif
				switch (rel[ctr].type)
				{
					case 1: /* R_PPC_ADDR32 */
						current_offset += rel[ctr].offset;
						//msg("PatchAddress32(%d, %X, GetSectionAddress(rel[ctr].section, rel[ctr].addend));\n",
						//		current_section, current_offset);
						PatchAddress32(current_section, current_offset, GetSectionAddress(rel[ctr].section, rel[ctr].addend));
						break;
					case 4: /* R_PPC_ADDR16_LO */
						current_offset += rel[ctr].offset;
						PatchAddressLO(current_section, current_offset, GetSectionAddress(rel[ctr].section, rel[ctr].addend));
						break;
					case 6: /* R_PPC_ADDR16_HA */
						current_offset += rel[ctr].offset;
						PatchAddressHA(current_section, current_offset, GetSectionAddress(rel[ctr].section, rel[ctr].addend));
						break;
					case 10: /* R_PPC_REL24 */
						current_offset += rel[ctr].offset;
						PatchAddress24(current_section, current_offset, GetSectionAddress(rel[ctr].section, rel[ctr].addend));
						break;
					case 201:
						current_offset += rel[ctr].offset;
#ifdef DEBUG
						msg("R_DOLPHIN_NOP\n");
#endif
						break;
					case 202:
						current_section = rel[ctr].section;
						current_offset  = 0;
#ifdef DEBUG
						msg("Current Section: %d\n", current_section);
#endif
						break;
					case 203:
#ifdef DEBUG
						msg("R_DOLPHIN_END\n");
#endif
						break;
					case 204:
#ifdef DEBUG
						msg("R_DOLPHIN_MRKREF\n");
#endif
						break;
					default:
#ifdef DEBUG
						msg("Unhandled ref type: %d\n", rel[ctr].type);
#endif
						break;
				}
				if (rel[ctr].type != 202)
				{
#ifdef DEBUG
					msg("Current Offset: 0x%08x\n", current_offset);
#endif
				}
#ifdef DEBUG
				if (ctr == 0x40) break;
#endif
			}
		}
		delete [] rel;
	}

	/* start analysis */
	for (int ii = 0; ii < rhdr.SectionCount; ii++)
	{
		if (sections[ii].Offset & SECTION_EXEC)
		{
			char buf[0x100];
			qsnprintf(buf, 0x100, ".section%u", ii);
			segment_t * segm = get_segm_by_name(buf);
			if (segm)
			{
				autoUnmark(segm->startEA, segm->endEA, AU_UNK);
				autoUnmark(segm->startEA, segm->endEA, AU_CODE);
				autoUnmark(segm->startEA, segm->endEA, AU_USED);
				autoUnmark(segm->startEA, segm->endEA, AU_FINAL);
			}
		}
	}
	//autoUnmark(START, START+sections[text].Length, 10);
	//autoUnmark(START, START+sections[text].Length, 20);
	//autoUnmark(START, START+sections[text].Length, 40);
	//autoUnmark(START, START+sections[text].Length, 200);
	//do_unknown_range(START, sections[text].Length, \
	//		DOUNK_EXPAND|DOUNK_DELNAMES);

	/* set naming */
	if (rhdr.Version == 1)
	{
		export_table_entry ent;
		uint32_t off = xtra.export_table_offset;
		uint32_t len = xtra.export_table_length;
		uint32_t nam = xtra.export_table_names;
		for(i=off; i<off+len; i+=sizeof(export_table_entry)) {
			qlseek(fp, i, SEEK_SET);
			qlread(fp, &ent, sizeof(export_table_entry));
			ent.name_off = swap32(ent.name_off);
			ent.section_off = swap32(ent.section_off);
			ent.section_num = swap32(ent.section_num);
			ent.elf_hash = swap32(ent.elf_hash);
			char nom[0x50];
			qlseek(fp, nam+ent.name_off, SEEK_SET);
			qlread(fp, &nom, 0x50);
			//if(ent.section_num != 1) continue;
			if (sections[ent.section_num].Offset & SECTION_EXEC)
			{
				add_func(GetSectionAddress(ent.section_num, ent.section_off), BADADDR);
			}
			set_name( \
				GetSectionAddress(ent.section_num, ent.section_off), \
				nom, SN_PUBLIC);
		}
	}
	
	delete [] sections;
}

/*-----------------------------------------------------------------
 *
 *   Loader Module Descriptor Blocks
 *
 */

extern "C" loader_t LDSC = {
  IDP_INTERFACE_VERSION,
  0, /* no loader flags */
  accept_file,
  load_file,
  NULL,
};
