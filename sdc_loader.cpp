/*
*      Interactive disassembler (IDA).
*      Copyright (c) 1990-2000 by Ilfak Guilfanov, <ig@datarescue.com>
*      ALL RIGHTS RESERVED.
*
*/

#define VERSION "1.0"
/*
*      SEGA DREAMCAST RAM Loader
*      Author: Dr. MefistO [Lab 313] <meffi@lab313.ru>
*/

#include <ida.hpp>
#include <idp.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>

idaman loader_t ida_module_data LDSC;

//--------------------------------------------------------------------------
static void print_version()
{
	static const char format[] = "SEGA DREAMCAST RAM loader plugin v%s;\nAuthor: Dr. MefistO [Lab 313] <meffi@lab313.ru>.";
	info(format, VERSION);
	msg(format, VERSION);
}

//--------------------------------------------------------------------------
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
	if (n != 0) return 0;
	
    int size = qlsize(li);

    if (size != 16 * 1024 * 1024 && size != 32 * 1024 * 1024)
        return 0;

	qstrncpy(fileformatname, "SEGA DREAMCAST RAM", MAX_FILE_FORMAT_NAME);

	return 1;
}

ea_t rams[] = { 0x8C000000, 0x0C000000, 0 };

ulong idaapi sizer(void *obj)
{
    ea_t *p = (ea_t *)obj;
    int count = 0;
    while (*p++) count++;
    return count;
}

char * idaapi getline(void *obj, ulong n, char *buf)
{
    ea_t *p = (ea_t *)obj;
    
    if (n == 0)
        qstrncpy(buf, "RAM Address", strlen("RAM Address") + 1);
    else
        qsnprintf(buf, 32, "0x%08.8x", p[n - 1]);

    return buf;
}

static void add_segment(ea_t start, ea_t end, const char *name, const char *class_name, const char *cmnt)
{
    if (!add_segm(0, start, end, name, class_name)) loader_failure();
    segment_t *segm = getseg(start);
    set_segment_cmt(segm, cmnt, false);
    doByte(start, 1);
}

//--------------------------------------------------------------------------
static char device[MAXSTR] = "SH7750";
static ioport_t *ports = NULL;
static size_t numports = 0;
static const char cfgname[] = "sh3.cfg";

static void load_symbols(void)
{
    free_ioports(ports, numports);
    ports = read_ioports(&numports, cfgname, device, sizeof(device), NULL);
}

static void apply_symbols(void)
{
    std::string name;
    for (size_t i = 0; i < numports; ++i)
    {
        name.assign(ports[i].name);
        size_t tail_pos = name.length() - 2;
        std::string tail = name.substr(tail_pos);

        if (tail[0] == '_')
        {
            if (tail == "_L")
                doDwrd(ports[i].address, 4);
            else if (tail == "_W")
                doWord(ports[i].address, 2);
            else if (tail == "_B")
                doByte(ports[i].address, 1);

            name = name.substr(0, tail_pos);
        }
        else if (tail == "WB") // "_WB"
        {
            doWord(ports[i].address, 2);
            name = name.substr(0, tail_pos);
        }
        else
            doDwrd(ports[i].address, 4);

        set_name(ports[i].address, name.c_str(), SN_NOWARN);
        set_cmt(ports[i].address, ports[i].cmt, false);
    }
}

//--------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort neflags, const char *fileformatname)
{
    if (ph.id != PLFM_SH) {
		set_processor_type("SH4", SETPROC_ALL | SETPROC_FATAL); // Motorola 68000
	}

    add_segment(0xFF000000, 0xFF000048, "CCN", "DATA", NULL);
    add_segment(0xFF200000, 0xFF200024, "UBC", "DATA", NULL);

    add_segment(0xFF800000, 0xFF80004C, "BSC", "DATA", NULL);

    add_segment(0xFF900000, 0xFF910000, "BSC_SDMR2", "BSS", NULL);
    add_segment(0xFF940000, 0xFF950000, "BSC_SDMR3", "BSS", NULL);
    add_segment(0xFFA00000, 0xFFA00044, "DMAC", "DATA", NULL);
    add_segment(0xFFC00000, 0xFFC00014, "CPG", "DATA", NULL);

    add_segment(0xFFC80000, 0xFFC80040, "RTC", "DATA", NULL);
    add_segment(0xFFD00000, 0xFFD00010, "INTC", "DATA", NULL);
    add_segment(0xFFD80000, 0xFFD80030, "TMU", "DATA", NULL);
    add_segment(0xFFE00000, 0xFFE00020, "SCI", "DATA", NULL);
    add_segment(0xFFE80000, 0xFFE80028, "SCIF", "DATA", NULL);
    add_segment(0xFFF00000, 0xFFF0000C, "HUDI", "DATA", NULL);

	unsigned int size = qlsize(li); // size of rom

	qlseek(li, 0, SEEK_SET);

    int choice = choose(rams, 30, sizer, getline, "Select Loading Address");

    if (!choice)
        error("Loading was canceled!");

    bool t = add_segm(0, rams[choice - 1], rams[choice - 1] + 0x02000000, "RAM", "DATA");

    file2base(li, 0, rams[choice - 1], rams[choice - 1] + size, FILEREG_PATCHABLE); // load rom to database

    load_symbols();
    apply_symbols();

	inf.af = 0
		| AF_FIXUP //        0x0001          // Create offsets and segments using fixup info
		| AF_MARKCODE  //     0x0002          // Mark typical code sequences as code
		| AF_UNK //          0x0004          // Delete instructions with no xrefs
		| AF_CODE //         0x0008          // Trace execution flow
		| AF_PROC //         0x0010          // Create functions if call is present
		| AF_USED //         0x0020          // Analyze and create all xrefs
		//| AF_FLIRT //        0x0040          // Use flirt signatures
		| AF_PROCPTR //      0x0080          // Create function if data xref data->code32 exists
		| AF_JFUNC //        0x0100          // Rename jump functions as j_...
		| AF_NULLSUB //      0x0200          // Rename empty functions as nullsub_...
		//| AF_LVAR //         0x0400          // Create stack variables
		//| AF_TRACE //        0x0800          // Trace stack pointer
		| AF_ASCII //        0x1000          // Create ascii string if data xref exists
		//| AF_IMMOFF //       0x2000          // Convert 32bit instruction operand to offset
		//AF_DREFOFF //      0x4000          // Create offset if data xref to seg32 exists
		| AF_FINAL //       0x8000          // Final pass of analysis
		;
	inf.af2 = 0
		| AF2_JUMPTBL  //    0x0001          // Locate and create jump tables
		//| AF2_DODATA  //     0x0002          // Coagulate data segs at the final pass
		//| AF2_HFLIRT  //     0x0004          // Automatically hide library functions
		| AF2_STKARG  //     0x0008          // Propagate stack argument information
		| AF2_REGARG  //     0x0010          // Propagate register argument information
		//| AF2_CHKUNI  //     0x0020          // Check for unicode strings
		//| AF2_SIGCMT  //     0x0040          // Append a signature name comment for recognized anonymous library functions
		| AF2_SIGMLT  //     0x0080          // Allow recognition of several copies of the same function
		| AF2_FTAIL  //      0x0100          // Create function tails
		| AF2_DATOFF  //     0x0200          // Automatically convert data to offsets
		//| AF2_ANORET  //     0x0400          // Perform 'no-return' analysis
		//| AF2_VERSP  //      0x0800          // Perform full SP-analysis (ph.verify_sp)
		//| AF2_DOCODE  //     0x1000          // Coagulate code segs at the final pass
		| AF2_TRFUNC  //     0x2000          // Truncate functions upon code deletion
		//| AF2_PURDAT  //     0x4000          // Control flow to data segment is ignored
		//| AF2_MEMFUNC //    0x8000          // Try to guess member function types
		;

	print_version();
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
	IDP_INTERFACE_VERSION,
	0,                            // loader flags
	//
	//      check input file format. if recognized, then return 1
	//      and fill 'fileformatname'.
	//      otherwise return 0
	//
	accept_file,
	//
	//      load file into the database.
	//
	load_file,
	//
	//      create output file from the database.
	//      this function may be absent.
	//
	NULL,
	//      take care of a moved segment (fix up relocations, for example)
	NULL
};
