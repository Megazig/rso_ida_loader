/*
 *  IDA Nintendo GameCube RSO Loader Module
 *  (C) Copyright 2010 Stephen Simpson
 *
 */

#ifndef __RSO_H__
#define __RSO_H__

#define START	0x80500000

/* Header Size = 100h bytes */
typedef struct {
	void * head;
	void * tail;
} queue_t;

typedef struct {
	void * next;
	void * prev;
} link_t;

typedef struct {
	unsigned int align;
	unsigned int bssAlign;
} module_v2;

typedef struct {
	unsigned int fixSize;
} module_v3;

#define USING_RSO 1
typedef struct {
	/* in .rso or .rel, not in .sel */
#if USING_RSO
	unsigned int ModuleID;
#endif
	/* in .rso or .rel or .sel */
	unsigned int Prev;
	unsigned int Next;
	unsigned int SectionCount;
	unsigned int SectionOffset;
	unsigned int PathOffset;
	unsigned int PathLength;
	unsigned int Version;

	/* type 1 or later */
	unsigned int BssSize;
	unsigned int RelOffset;
	unsigned int ImpOffset;
	unsigned int ImpSize;
	unsigned char PrologSection;
	unsigned char EpilogSection;
	unsigned char UnresolvedSection;
	unsigned char BssSection;
	unsigned int Prolog;
	unsigned int Epilog;
	unsigned int Unresolved;

	/* type 2 or later */
	unsigned int align;
	unsigned int bssAlign;

	/* type 3 or later */
	unsigned int fixSize;
} rsohdr;

typedef struct {
	unsigned int internal_table_offset; // 30
	unsigned int internal_table_length; // 34
	unsigned int external_table_offset; // 38
	unsigned int external_table_length; // 3C
	unsigned int export_table_offset; // 40
	unsigned int export_table_length; // 44
	unsigned int export_table_names; // 48
	unsigned int import_table_offset; // 4C
	unsigned int import_table_length; // 50
	unsigned int import_table_names; // 54
} module_v1_extra;

/* usually right after header */
typedef struct {
	unsigned int Offset;
	unsigned int Length;
} section_entry;

/* usually after section list */
/* usually an export then import */
typedef struct {
	unsigned int offset;
	unsigned int length;
	unsigned int names;
} ex_im_port_entry;

typedef struct {
	unsigned int name_off;
	unsigned int section_off;
	unsigned int section_num;
	unsigned int elf_hash;
} export_table_entry;

#define SECTION_EXEC 0x1
#define SECTION_OFF(off) (off&~1)

typedef struct {
	unsigned int id;
	unsigned int offset;
} import_info;

typedef struct {
	unsigned short offset; // byte offset from previous entry
	unsigned char  type;
	unsigned char  section;
	unsigned int   addend;
} rel_t;

const char * rel_names[] = {
	"R_PPC_NONE",
	"R_PPC_ADDR32",
	"R_PPC_ADDR24",
	"R_PPC_ADDR16",
	"R_PPC_ADDR16_LO",
	"R_PPC_ADDR16_HI",
	"R_PPC_ADDR16_HA",
	"R_PPC_ADDR14",
	"R_PPC_ADDR14_BRTAKEN",
	"R_PPC_ADDR14_BRNTAKEN",
	"R_PPC_REL24",
	"R_PPC_REL14",
};
                                    /* calculation */
#define R_PPC_NONE            0     /* none */
#define R_PPC_ADDR32          1     /* S + A */
#define R_PPC_ADDR24          2     /* (S + A) >> 2 */
#define R_PPC_ADDR16          3     /* S + A */
#define R_PPC_ADDR16_LO       4
#define R_PPC_ADDR16_HI       5
#define R_PPC_ADDR16_HA       6
#define R_PPC_ADDR14          7
#define R_PPC_ADDR14_BRTAKEN  8
#define R_PPC_ADDR14_BRNTAKEN 9
#define R_PPC_REL24           10   /* (S + A - P) >> 2 */
#define R_PPC_REL14           11

#define R_DOLPHIN_NOP     201 // C9h current offset += rel.offset
#define R_DOLPHIN_SECTION 202 // CAh current offset = rel.section
#define R_DOLPHIN_END     203 // CBh
#define R_DOLPHIN_MRKREF  204 // CCh

/* OSSetStringTable(const void * stringTable);
 * OSLink(OSModuleInfo* newModule, void* bss);
 * OSLinkFixed(OSModuleInfo* newModule, void* bss);
 * OSUnlink(OSModuleInfo* oldModule);
 * OSSearchModule(void* ptr, u32* section, u32* offset);
 * OSNotifyLink
 * OSNotifyUnlink
 * OSNotifyPreLink
 * OSNotifyPostLink
 */

#endif
