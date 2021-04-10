#include "Capstone.h"
#include "BreakPoint.h"
csh Capstone::Handle = { 0 };
cs_opt_mem Capstone::OptMem = { 0 };
			
// initialize 
void Capstone::Init()
{
	//分配堆空间回调函数
	OptMem.calloc = calloc;
	OptMem.free = free;
	OptMem.malloc = malloc;
	OptMem.realloc = realloc;
	OptMem.vsnprintf = vsnprintf;

	//注册堆空间管理组函数
	cs_option(NULL, CS_OPT_MEM, (size_t)&OptMem);

	//打开一个句柄
	cs_open(CS_ARCH_X86, CS_MODE_32, &Capstone::Handle);
}

//反汇编指定条数的语句
void Capstone::DisAsm(DEBUG_EVENT debug_event,HANDLE Handle, LPVOID Addr, DWORD Count)
{
	//用来读取指令位置内存的缓冲区信息
	cs_insn* ins = nullptr;
	PCHAR buff = new CHAR[Count * 0x10]{ 0 };

	//指定读取长度的内存空间
	DWORD dwWrite = 0;
	ReadProcessMemory(Handle, Addr, buff, Count * 0x10, &dwWrite);
	//获取 汇编代码
	int count = cs_disasm(Capstone::Handle, 
		(uint8_t*)buff, Count * 16, (uint64_t)Addr, 0, &ins);

	//for 条件在少数情况下会产生问题，可能需要修改条件
	// 某些时候，设置段点后悔生成无效指令
	for (DWORD i = 0;i<Count;++i)
	{
		printf("%08x\t", (UINT)ins[i].address);
		for (uint16_t j = 0; j < 16; j++)
		{
			if (j < ins[i].size)
				printf("%02x", ins[i].bytes[j]);
			else
				printf("  ");
		}
		//输出对应的反汇编
		printf("%s %s", ins[i].mnemonic, ins[i].op_str);
		//输出符号
		if (!strcmp(ins[i].mnemonic, "jmp") || !strcmp(ins[i].mnemonic, "call"))
		{
			char* buffer = nullptr;
			buffer = ins[i].op_str;
			while (*buffer != '0')
			{
				buffer++;
			}
			//buffer += 2;
			char addrbuffer[2000] = { 0 };

			DWORD64 dwAddr = -0;
			memcpy(buffer + 10, "", 1);
			//sscanf_s(ins[i].op_str, "%08x", &dwAddr);
			sscanf_s(buffer, "%010x", &dwAddr);
			BreakPoint::GetSymbolFromAddr(debug_event, Handle, addrbuffer, (LPVOID)dwAddr);
			printf("\t%s\n", addrbuffer);
		}
		else
			printf("\n");
	}
	printf("\n");
	//释放动态内存分配的空间
	delete[] buff;
	cs_free(ins, count);
}

//return order lenth
int Capstone::ReOrderLenth(HANDLE Handle, LPVOID Addr)
{
	//用来读取指令位置内存的缓冲区信息
	cs_insn* ins = nullptr;
	PCHAR buff = new CHAR[0x10]{ 0 };

	//指定读取长度的内存空间
	DWORD dwWrite = 0;
	ReadProcessMemory(Handle, Addr, buff, 0x10, &dwWrite);
	//获取 汇编代码
	int count = cs_disasm(Capstone::Handle,
		(uint8_t*)buff, 0x10, (uint64_t)Addr, 0, &ins);
	return ins->size;
}





