#include "BreakPoint.h"
#include <windows.h>
#include "Capstone.h"
#include <TlHelp32.h>
#include <Winternl.h>
#include <cstringt.h>
#include <DbgHelp.h>

#include "XEDParse/XEDParse.h"

#pragma comment (lib,"Ntdll.lib")

#ifdef _WIN64
#pragma comment (lib,"XEDParse/x64/XEDParse_x64.lib")
#else
#pragma comment (lib,"XEDParse/x86/XEDParse_x86.lib")
#endif // _WIN64

#pragma comment (lib,"Dbghelp.lib")

using namespace ATL;


// DR7寄存器结构体
typedef struct _DBG_REG7
{
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// 保留的无效空间
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} Dr7, *PDr7;


//vector of BreakPoint
vector<BREAKPOINTINFO> BreakPoint::vecBreakpoint;
vector<MEMBREAKPOINTINFO> BreakPoint::vecMemBreakPoint;
PMEMBREAKPOINTINFO BreakPoint::membreakpoint;
 HBPINFO BreakPoint::hbpSturct;

//set software breakpoint
void BreakPoint::SetCcBreakPoint(HANDLE process_handle, LPVOID addr)
{
	// 软件断点: 当 CPU 在执行指令的时候，遇到了 int 3
	// 指令，就会产生一个 3 号异常，eip 指向的是 int 3
	// 的下一条指令，通过向目标指令的首字节中写入 int 3 
	// 可以实现软件断点
	
	// 0. create struct of save breakpoint information;
	BREAKPOINTINFO info = { addr };
	DWORD old_protect = 0;
	// 1. read opcode of destination address to repair program
	ReadProcessMemory(process_handle, addr, &info.old_opcode, 1, NULL);

	VirtualProtectEx(process_handle, addr, 1, PAGE_EXECUTE_READWRITE, &old_protect);
	// 2. write \xcc to location
	WriteProcessMemory(process_handle, addr, "\xCC", 1, NULL);

	VirtualProtectEx(process_handle, addr, 1, old_protect, &old_protect);
	// 3. push_back breakpoint 
	std::vector<BREAKPOINTINFO>::iterator itor = vecBreakpoint.begin();
	for (; itor != vecBreakpoint.end(); itor++)
	{
		if (itor->addr == addr)
		{
			return;
		}
	}
	vecBreakpoint.push_back(info);
}

// repair software breakpoint(int3)
void BreakPoint::FixCcBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr)
{
	// 修复软件断点: 当软件断点断下后,eip 指向的是下一条
	// 需要将 eip - 1，因为 0xCC 是一个字节，然后为了不影
	// 响代码的执行流程，需要将原有的 OPCODE 恢复。
	
	// cycle vector to find need repair breakpoint;
	for (int j = 0; j < vecBreakpoint.size(); j++)
	{
		// repair only if address is  the same,
		// otherwise one error will be occur
		if (vecBreakpoint[j].addr == addr)
		{
			// 1. get register information and eip - = 1
			CONTEXT context = { CONTEXT_CONTROL };
			GetThreadContext(thread_handle, &context);
			context.Eip -= 1;
			SetThreadContext(thread_handle, &context);

			// 2.repair address
			WriteProcessMemory(process_handle, addr,
				&vecBreakpoint[j].old_opcode, 1, NULL);

			// 3. forever breakpoint(sign location)/normal breakpoint
			//vecBreakpoint.erase(vecBreakpoint.begin() + j);
			break;
		}
	}
	
}

// set a single step (tf)
void BreakPoint::SetTfBreakPoint(HANDLE thread_handle)
{
	// 单步断点: 通过 CPU 中 efalgs 提供的 TF 标志位
	// 完成的。当CPU在执行指令之后，会检查当前的 TF 位
	// 是否开启，如果开启了，就会触发一个单步异常，并且
	// 会将 TF 标志位重新置 0。

	// 1. Get sign location information 
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(thread_handle, &context);
	context.EFlags |= 0x100;
	SetThreadContext(thread_handle, &context);
}

// set hardware breakpoint (DrN)
void BreakPoint::SetHdBreakPoint(HANDLE thread_handle,LPVOID addr, int type, int len)
{
	// 硬件的执行断点术语错误类异常,断下的位置就是异常发生的位
	// 置,读写断点是设置给内存地址的,属于陷阱类异常.[读写断点是
	// 设置给中括号内的内容的

	// 硬件断点: 基于调试寄存器实现的断点，设置硬件断点使用到了
	// Dr0~Dr3 以及 Dr7，Dr0~De3 保存的是想要设置断点的位置，
	// Dr7 用于描述断点的类型和断点覆盖的范围。因为保存地址的调
	// 试寄存器只有 4 个，所以硬件断点最多 4 个。

	// 当 RW 的值是 0 的时候，表示设置硬件执行断点，此时，Len
	// 位必须为 0，RW 表示的是类型，len 表示范围。
	hbpSturct.addr = addr;
	hbpSturct.len = len;
	hbpSturct.type = type;
	//对齐
	ULONG_PTR uaddr = (ULONG_PTR)addr;
	if (len == 1)
	{
		uaddr = (ULONG_PTR)addr - (ULONG_PTR)addr % 2;
	}
	else if (len == 3)
	{
		uaddr = (ULONG_PTR)addr - (ULONG_PTR)addr % 4;
	}
	else if (len > 3)
	{
		return;
	}
	else if (len == 0)
	{
	}
	else return;

	// get target process sign information;
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread_handle, &context);

	// Get Dr7 register , save used breakpoint
	PDr7 Dr7 = (PDr7)&context.Dr7;

	// judgment used or not
	if (Dr7->L0 == 0)
	{
		// set basis information 
		context.Dr0 = (ULONG_PTR)uaddr;
		Dr7->RW0 = type;
		Dr7->LEN0 = len;
		// Enable breakpoint
		Dr7->L0 = 1;
	}
	else if (Dr7->L1 == 0)
	{
		context.Dr1 = (ULONG_PTR)uaddr;
		Dr7->RW1 = type;
		Dr7->LEN1 = len;
		Dr7->L1 = 1;
	}
	else if (Dr7->L2 == 0)
	{
		context.Dr2 = (ULONG_PTR)uaddr;
		Dr7->RW2 = type;
		Dr7->LEN2 = len;
		Dr7->L2 = 1;
	}
	else if (Dr7->L3 == 0)
	{
		context.Dr3 = (ULONG_PTR)uaddr;
		Dr7->RW3 = type;
		Dr7->LEN3 = len;
		Dr7->L3 = 1;
	}
	else
	{
		printf("没有空闲的硬件断点位置!\n");
	}

	
	SetThreadContext(thread_handle, &context);
}


//set hardware breakpoint(DrN)
BOOL BreakPoint::FixHdBreakPoint(HANDLE thread_handle, LPVOID addr, BOOL bButton)
{
	// 修复硬件断点的原理: 当硬件断点断下后,Dr6的最低 4 位
	// 标记了是哪一个硬件断点断下了,找到这个硬件断点对应的
	// LN,将这个位置设置为0就可以了.

	//	Get target thread register 
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS|CONTEXT_FULL };
	GetThreadContext(thread_handle, &context);

	// Get register of Dr7 
	PDr7 Dr7 = (PDr7)&context.Dr7;
	BOOL cbButton = FALSE;
	//judgment breakpoint that  who trigger off 
	switch (context.Dr6 & 0xF)
	{
	case 1:
		Dr7->L0 = 0; break;
	case 2:
		Dr7->L1 = 0; break;
	case 4:
		Dr7->L2 = 0; break;
	case 8: 
		Dr7->L3 = 0; break;
	default:
		cbButton = TRUE;
		break;
	}

	SetThreadContext(thread_handle, &context);
	return cbButton;
}

//forever breakpoint
void BreakPoint::ResHdBreakPoint(HANDLE thread_handle, LPVOID addr)
{
	hbpSturct;
	if (hbpSturct.addr == addr)
	{
		return;
	}
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL };
	GetThreadContext(thread_handle, &context);
	if (context.Dr0 == (ULONG_PTR)hbpSturct.addr)
	{
	}
	else if(context.Dr1 == (ULONG_PTR)hbpSturct.addr)
	{

	}
	else if (context.Dr2 == (ULONG_PTR)hbpSturct.addr)
	{

	}
	else if (context.Dr3 == (ULONG_PTR)hbpSturct.addr)
	{

	}
	else SetHdBreakPoint(thread_handle, hbpSturct.addr, hbpSturct.type, hbpSturct.len);
}

// 内存断点: 基于分页属性设置的断点.当一个分页的数据不可读写
// 时,会触发设备访问异常. 当将一个地址设置为不可访问后,他所在
// 的整个分页就都不可访问了.此时可以通过异常结构中的 infomation 
// 获取到断下的原因(0,1,8),第二个参数是产生异常的地址,使用这个
// 参数和设置的断点位置进行比较,可以找到这个断点. 如果不是我们需
// 要断下的地方,就需要恢复内存访问属性,并且单步执行一次后重新设置
// 内存访问属性,重复的进行这一个操作,直到参数一对应的是我i们设置的
// 断点类型且参数二的地址和我们设置的地址相同,就成功断下,期间设置的
// 所有断点,都不应该被用户察觉.

//Set memory access breakpoint
void BreakPoint::SetMemBreakPoint(HANDLE process_handle, LPVOID addr,int mode)
{
	BreakPoint::membreakpoint;
	if (membreakpoint == nullptr)
	{
		membreakpoint = new MEMBREAKPOINTINFO;
	}
	membreakpoint->addr = addr;
	BOOL RES = VirtualProtectEx(process_handle,addr, 1, mode, &membreakpoint->old_protect);
	//vecMemBreakPoint.push_back(BreakPoint::membreakpoint);
}

//repair memory access breakpoint
BOOL BreakPoint::RepairMemBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr,BOOL bButton)
{

	if (membreakpoint == nullptr)
	{
		return TRUE;
	}
	if (membreakpoint->addr == addr)
	{
		VirtualProtectEx(process_handle,addr,1, membreakpoint->old_protect, &membreakpoint->old_protect);
		if (bButton)
		{
			delete membreakpoint;
			membreakpoint = nullptr;
			return TRUE;
		}	
		SetTfBreakPoint(thread_handle);
		return TRUE;
	}
	else
	{
		//VirtualProtectEx(process_handle, membreakpoint->addr, 1, membreakpoint->old_protect, &membreakpoint->old_protect);
		VirtualProtectEx(process_handle, addr, 1, membreakpoint->old_protect, &membreakpoint->old_protect);
		SetTfBreakPoint(thread_handle);
		return FALSE;
	}
	
	
}

//restore breakpoint
void BreakPoint::ResBreakpoint(HANDLE thread_handle)
{
	for (auto & P: vecBreakpoint)
	{
		SetCcBreakPoint(thread_handle, P.addr);
	}
}

//restore Memory breakpoint
BOOL BreakPoint::ResMemBreakPoint(HANDLE process_handle, LPVOID Addr)
{	
	//membreakpoint
	//内存断点只有一个 检测是否存在
	if (membreakpoint == nullptr)
	{
		return FALSE;
	}
	//分别对0x1000取整  判断是否在相同页
	//BOOL res = ((ULONGLONG)membreakpoint->addr / 0x1000) == ((ULONGLONG)Addr / 0x1000) ? TRUE : FALSE;
	BOOL res = TRUE;
	if (res)
	{
		//将被修复的内存重新设置为异常状态 （永久状态）
		SetMemBreakPoint(process_handle, membreakpoint->addr, membreakpoint->old_protect);
		return TRUE;
	}
	return FALSE;
}

//set single step  out
void BreakPoint::SetToBreakPoint(HANDLE process_handle,HANDLE thread_handle, LPVOID Addr)
{

	BREAKPOINTINFO info = { Addr };

	// 1. read opcode of destination address to repair program
	ReadProcessMemory(process_handle, info.addr, &info.old_opcode, 1, NULL);

	//set software breakpoint
	if (info.old_opcode == 0xe8 )
	{
		info.addr = (LPVOID)((long long)info.addr + 5);
		SetCcBreakPoint(process_handle, info.addr);
	}
	else if (info.old_opcode == 0xf3)
	{
		info.addr = (LPVOID)((long long)info.addr + 2);
		SetCcBreakPoint(process_handle, info.addr);
	}
	else //set single step breakpoint
		SetTfBreakPoint(thread_handle);
}

//view stack
void BreakPoint::ViewStack(HANDLE process_handle, HANDLE thread_handle)
{
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(thread_handle,&context);
	BREAKPOINTINFO info = { 0 };
	DWORD ESP = context.Esp;
	DWORD dwWrite = 0;
	BYTE buffer[512] = { 0 };
	ReadProcessMemory(process_handle, (LPVOID)ESP, buffer, 512, &dwWrite);
	INT index = 0;
	while (ESP != context.Ebp)
	{
		printf("%08x\n", ((DWORD*)buffer)[index++]);
		ESP += 4;
	}
}

//view memory
void BreakPoint::ViewMem(HANDLE process_handle, LPVOID Addr, INT count)
{
	DWORD dwWrite = 0;
	BYTE * buffer = new BYTE[count* 10 * 0x10]{ 0 };
	ReadProcessMemory(process_handle, Addr, buffer, count * 10 * 0x10, &dwWrite);
	INT index = 0;
	for (size_t j = 0; j < count; j++)
	{
		for (size_t i = 0; i < 10; i++)
		{
			printf("%08x ", ((DWORD*)buffer)[index++]);
		}
		printf("\n");
	}
}

//view Register
void BreakPoint::ViewReg(HANDLE thread_handle)
{
	CONTEXT context = { CONTEXT_ALL };
	GetThreadContext(thread_handle, &context);

	printf("EAX:%08x\n", context.Eax);
	printf("ECX:%08x\n", context.Ecx);
	printf("EDX:%08x\n", context.Edx);
	printf("EBX:%08x\n", context.Ebx);
	printf("ESP:%08x\n", context.Esp);
	printf("EBP:%08x\n", context.Ebp);
	printf("ESI:%08x\n", context.Esi);
	printf("EDI:%08x\n", context.Edi);

	printf("\nEIP:%08x\n\n", context.Eip);

	printf("Dr0:%08x\n", context.Dr0);
	printf("Dr1:%08x\n", context.Dr1);
	printf("Dr2:%08x\n", context.Dr2);
	printf("Dr3:%08x\n", context.Dr3);
	printf("Dr6:%08x\n", context.Dr6);
	printf("Dr7:%08x\n", context.Dr7);
}//"\x12\0"  

//view module
void BreakPoint::ViewModule(DEBUG_EVENT debugevent)
{
	HANDLE ModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, debugevent.dwProcessId);
	MODULEENTRY32 stcMd32;
	stcMd32.dwSize = sizeof(stcMd32);
	if (Module32First(ModuleSnap, &stcMd32))
	{
		do
		{
			stcMd32;
			printf(stcMd32.szModule);
			printf("\n");
		} while (Module32Next(ModuleSnap, &stcMd32));
	}
	CloseHandle(ModuleSnap);
}

//modify memory 
void BreakPoint::ModifyMem(HANDLE process_handle, LPVOID addr, char* changeaddr)
{
	MEMORYINFO info = { addr };

	// 1. read opcode of destination address to repair program
	int bufferlen = strlen(changeaddr);

	for (int i = 0; i< bufferlen/2; ++i)
	{
		int tmp = changeaddr[i];
		changeaddr[i] = changeaddr[bufferlen - i - 1];
		changeaddr[bufferlen - i - 1] = tmp;
	}

	info.memvalue = new BYTE[bufferlen]{ 0 };
	DWORD size; 
	BOOL RES = ReadProcessMemory(process_handle, addr, &info.memvalue, bufferlen, &size);

	DWORD old_protect = 0;
	VirtualProtectEx(process_handle, addr, 1, PAGE_READWRITE, &old_protect);

	RES = WriteProcessMemory(process_handle, addr, changeaddr, bufferlen, &size);
	VirtualProtectEx(process_handle, addr, 1, old_protect, &old_protect);
}

//modify register
void BreakPoint::ModifyRegister( HANDLE thread_handle,char* registers,DWORD value)
{
	CONTEXT context = { CONTEXT_ALL };
	GetThreadContext(thread_handle, &context);
	if (!strcmp(registers, "EAX"))
	{
		context.Eax = value;
	}
	else if (!strcmp(registers, "ECX"))
	{
		context.Ecx = value;
	}
	else if (!strcmp(registers, "EDX"))
	{
		context.Edx = value;
	}
	else if (!strcmp(registers, "EBX"))
	{
		context.Ebx = value;
	}
	else if (!strcmp(registers, "ESP"))
	{
		context.Esp = value;
	}
	else if (!strcmp(registers, "EBP"))
	{
		context.Ebp = value;
	}
	else if (!strcmp(registers, "ESI"))
	{
		context.Esi = value;
	}
	else if (!strcmp(registers, "EDI"))
	{
		context.Edi = value;
	}
	else if (!strcmp(registers, "EIP"))
	{
		context.Eip = value;
	}
	BOOL res = SetThreadContext(thread_handle, &context);
}

//modify compilation
void BreakPoint::ModifyCompilation(HANDLE process_handle, LPVOID addr, char* compilationcode)
{
	XEDPARSE xed = { 0 };
	xed.cip = (ULONGLONG)addr;
	strcpy_s(xed.instr, XEDPARSE_MAXBUFSIZE, compilationcode);

	if (XEDPARSE_OK != XEDParseAssemble(&xed))
	{
		printf("指令错误：%s\n", xed.error);
		return;
	}
	xed.dest;
	DWORD old_protect = 0;
	DWORD size = 0;

	PCHAR buff = new CHAR[0x10]{ 0 };

	//指定读取长度的内存空间
	DWORD dwWrite = 0;
	cs_insn* ins = nullptr;
	DWORD xedlen = xed.dest_size;
	DWORD inslen = 0;
	while (xedlen>= inslen)
	{
		ReadProcessMemory(process_handle, (LPCVOID)((DWORD)addr+ inslen), buff, 0x10, &dwWrite);
		//获取 汇编代码
		int count = cs_disasm(Capstone::Handle,
			(uint8_t*)buff, 16, (uint64_t)addr, 0, &ins);
		inslen += ins->size;
	}

	BOOL RES = VirtualProtectEx(process_handle, addr, 1, PAGE_READWRITE, &old_protect);

	RES = WriteProcessMemory(process_handle, addr, xed.dest, xed.dest_size, &size);

	//填充nop
	for (int i = 0; i < inslen - xedlen; ++i)
	{
		WriteProcessMemory(process_handle, (LPVOID)((DWORD)addr + xedlen + i), "\x90", 1, &size);
	}

	RES = VirtualProtectEx(process_handle, addr, 1, old_protect, &old_protect);
}

//forever breakpoint
//************************************
// 方法:   ForeverBreakPoint
// 全名:   BreakPoint::ForeverBreakPoint
// 访问:   public static 
// 返回:   BOOL
// 作用：  设置永久断点
// 限定符:
// 参数:   HANDLE process_handle
// 参数:   HANDLE thread_handle
//************************************
BOOL BreakPoint::ForeverBreakPoint(HANDLE process_handle, HANDLE thread_handle)
{
	BOOL RES = FALSE;
	//int3 
	//把被删除的断点重新设置
	//vecBreakpoint为保存断点的结构体
	for (auto P : vecBreakpoint)
	{
		SetCcBreakPoint(process_handle, P.addr);
		RES = TRUE;
	}
	return RES;
}

//条件断点
BOOL BreakPoint::ConditionBreakPoint(HANDLE process_handle, HANDLE thread_handle,LPVOID addr, char* registers, int value)
{
	BOOL RES = FALSE;
	//每次设置单步步入断点 然后获去CONTEXT 获取对应寄存器的值
	CONTEXT context = { CONTEXT_ALL };
	GetThreadContext(thread_handle, &context);
	if (!strcmp(registers, "EAX"))
	{
		if (context.Eax == value)
		{
			//SetTfBreakPoint(thread_handle);
			RES = TRUE;
		}
	}
	else if (!strcmp(registers, "ECX"))
	{
		
		if (context.Ecx == value)
		{
			//SetTfBreakPoint(thread_handle);
			RES = TRUE;
		}
	}
	else if (!strcmp(registers, "EDX"))
	{
		
		if (context.Edx == value)
		{
			//SetTfBreakPoint(thread_handle);
			RES = TRUE;
		}
	}
	else if (!strcmp(registers, "EBX"))
	{

		if (context.Ebx == value)
		{
			//SetTfBreakPoint(thread_handle);
			RES = TRUE;
		}
	}
	else if (!strcmp(registers, "ESP"))
	{
		
		if (context.Esp == value)
		{
			//SetTfBreakPoint(thread_handle);
			RES = TRUE;
		}
	}
	else if (!strcmp(registers, "EBP"))
	{
		
		if (context.Ebp == value)
		{
			//SetTfBreakPoint(thread_handle);
			RES = TRUE;
		}
	}
	else if (!strcmp(registers, "ESI"))
	{
		
		if (context.Esi == value)
		{
			//SetTfBreakPoint(thread_handle);
			RES = TRUE;
		}
	}
	else if (!strcmp(registers, "EDI"))
	{
		
		if (context.Edi == value)
		{
			//SetTfBreakPoint(thread_handle);
			RES = TRUE;
		}
	}
	else if (!strcmp(registers, "EIP"))
	{
		
		if (context.Eip == value)
		{
			//SetTfBreakPoint(thread_handle);
			RES = TRUE;
		}
	}
	if (RES)
	{
		DWORD index = 0;
		std::vector<BREAKPOINTINFO>::iterator itor = vecBreakpoint.begin();
		for (auto & P: vecBreakpoint)
		{
			if (P.addr == addr)
				break;
			else
				index++;
		}
		vecBreakpoint.erase(itor + index);
		return TRUE;
	}
	return FALSE;
}

//隐藏PEB
BOOL BreakPoint::HideDebugger(HANDLE process_handle)
{
	typedef struct

	{
		DWORD ExitStatus;					// 接收进程终止状态

		DWORD PebBaseAddress;				// 接收进程环境块地址

		DWORD AffinityMask;					// 接收进程关联掩码

		DWORD BasePriority;					// 接收进程的优先级类

		ULONG UniqueProcessId;				// 接收进程ID

		ULONG InheritedFromUniqueProcessId; //接收父进程ID

	} PROCESS_BASIC_INFORMATION;

	
	//储存进程相关信息 主要是获得PEB
	PROCESS_BASIC_INFORMATION processinfo = { 0 };

	//获得PEB在目标进程的位置
	NtQueryInformationProcess(
		process_handle,
		ProcessBasicInformation,
		&processinfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL);

	DWORD dwTmp = 0;
	DWORD old_protect = 0;
	//向目标 begingdebugger 位置写入空（0）

	BOOL RES = WriteProcessMemory(process_handle, (LPVOID)(processinfo.PebBaseAddress + 0x02), "", 1, &dwTmp);
	
	return TRUE;
}

//************************************
// 方法:   GetTables
// 全名:   BreakPoint::GetTables
// 访问:   public static 
// 返回:   BOOL
// 作用：  显示指定DLL导出表导入表
// 限定符:
// 参数:   DEBUG_EVENT debugevent
// 参数:   char * dlllName
//************************************

BOOL BreakPoint::GetTables(DEBUG_EVENT debugevent,char* dlllName)
{

	char dllpath[MAX_PATH] = { 0 };
	HANDLE ModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, debugevent.dwProcessId);
	MODULEENTRY32 stcMd32;
	stcMd32.dwSize = sizeof(stcMd32);
	if (Module32First(ModuleSnap, &stcMd32))
	{
		do
		{
			if(!strcmp(stcMd32.szModule, dlllName))
			{
				strcpy_s(dllpath, MAX_PATH,stcMd32.szExePath);
				break;
			}
		} while (Module32Next(ModuleSnap, &stcMd32));
	}
	CloseHandle(ModuleSnap);

	if (dllpath == 0)
	{
		printf("无此模块\n");
		return FALSE;
	}

	HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, debugevent.dwThreadId);
	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, debugevent.dwProcessId);

	//CA2W buffer(dllpath);
	wchar_t buffer[MAX_PATH] = { 0 };
	MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, dllpath, sizeof(dllpath), buffer, MAX_PATH);
	MyPe* dllPe = new MyPe(buffer);
	if (dllPe->m_buf == nullptr)
	{
		printf("解析失败\n");
		return FALSE;
	}
	PIMAGE_EXPORT_DIRECTORY pExportTable = dllPe->GetExportTable();
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = dllPe->GetImportTable();

	if (pExportTable == NULL)
	{
		printf("无导出表\n");
	}
	else
	{
		printf("Base:%d\n", pExportTable->Base);
		printf("NumberOfFunctions:%d\n", pExportTable->NumberOfFunctions);
		printf("NumberOfNames:%d\n", pExportTable->NumberOfNames);
		printf("地址表			");
		DWORD FOA2 = dllPe->RVA2FOA(pExportTable->AddressOfFunctions);
		DWORD* addTable = (DWORD*)(FOA2 + (DWORD)dllPe->pDosHeader);
		//for (size_t i = 0; i < pExportTable->NumberOfFunctions; i++)
		//{
		//	printf("%x\n", addTable[i]);
		//}
		printf("序号表			");
		DWORD FOA3 = dllPe->RVA2FOA(pExportTable->AddressOfNameOrdinals);
		WORD* indexTable = (WORD*)(FOA3 + (DWORD)dllPe->pDosHeader);
		//for (size_t i = 0; i < pExportTable->NumberOfNames; i++)
		//{
		//	printf("%x\n", indexTable[i]+pExportTable->Base);
		//}
		printf("函数名\n");
		DWORD FOA4 = dllPe->RVA2FOA(pExportTable->AddressOfNames);
		DWORD* NameTable = (DWORD*)(FOA4 + (DWORD)dllPe->pDosHeader);
		//for (size_t i = 0; i < pExportTable->NumberOfNames; i++)
		//{
		//	//函数名
		//	DWORD tmpFOA = RVA2FOA(NameTable[i]);
		//	char* Name = (char*)(tmpFOA + (DWORD)pDosHeader);
		//	printf("%s ", Name);
		//	//序号表
		//	printf("%14x ", indexTable[i] + pExportTable->Base);
		//	//地址
		//	printf("%26x \n", addTable[indexTable[i]]);
		//}
		for (size_t i = 0; i < pExportTable->NumberOfFunctions; i++)
		{
			if (addTable[i] == 0)
			{
				continue;
			}
			//函数地址
			printf("%x ", addTable[i]);
			//函数序号
			//函数名
			BOOL bButton = TRUE;
			for (size_t j = 0; j < pExportTable->NumberOfNames; j++)
			{
				if (indexTable[j] == i)
				{
					printf("%x ", indexTable[i] + pExportTable->Base);
					DWORD tmpFOA = dllPe->RVA2FOA(NameTable[i]);
					char* Name = (char*)(tmpFOA + (DWORD)dllPe->pDosHeader);
					printf("%s \n", Name);
					bButton = FALSE;
					break;
				}
			}
			if (bButton)
			{
				printf("null ");
				printf("null \n");
			}
		}
	}
	if (pImportTable == NULL)
	{
		printf("无导入表");
	}
	else
	{
		//size_t numOfImportTable = pOptionalHeader->DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	printf("导入表\n");
	//for (size_t i = 0; i < numOfImportTable; i++);
	while (pImportTable->Name != NULL)
	{
		printf("导入的PE文件名称：");
		char * dwName = (char *)(dllPe->RVA2FOA(pImportTable->Name) + (DWORD)dllPe->pDosHeader);
		printf("%s\n", dwName);
		printf("导入的函数\n");
		//DWORD FirstThunk_FOA = RVA2FOA(pImportTable->OriginalFirstThunk);//INT
		DWORD FirstThunk_FOA = dllPe->RVA2FOA(pImportTable->FirstThunk);//IAT
		PIMAGE_THUNK_DATA thunk =
			(PIMAGE_THUNK_DATA)(FirstThunk_FOA + (DWORD)dllPe->pDosHeader);
		printf("Hint  Name \n");
		while (thunk->u1.Ordinal)
		{
			if (!IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
			{
				PIMAGE_IMPORT_BY_NAME functionInfo =
					(PIMAGE_IMPORT_BY_NAME)(dllPe->RVA2FOA(thunk->u1.AddressOfData) + (DWORD)dllPe->pDosHeader);
				printf("%04x %s\n", functionInfo->Hint, functionInfo->Name);
			}
			else
			{
				printf("%04x %s\n", thunk->u1.Ordinal & 0xffff, "(NULL)");
			}
			thunk++;
		}
		pImportTable++;
	}
	}

}

//初始化符号处理器
BOOL BreakPoint::InitalSymbol(DEBUG_EVENT debugevent, HANDLE process_handle)
{
	BOOL RES = FALSE;
	CHAR path[MAX_PATH] = { 0 };
	//初始化符号
	RES = SymInitialize(process_handle, "./Symbol", FALSE);
	//模块加载基址
	DWORD EntryBase = (DWORD)debugevent.u.CreateProcessInfo.lpStartAddress;
	//获取模块路径
	GetFinalPathNameByHandle(debugevent.u.LoadDll.hFile, path, MAX_PATH, NULL);
	//加载符号文件
	SymLoadModule64(process_handle,
		debugevent.u.LoadDll.hFile,
		path, NULL,
		(DWORD64)debugevent.u.LoadDll.lpBaseOfDll , NULL);

	return TRUE;
}

//通过地址获取符号
BOOL BreakPoint::GetSymbolFromAddr(DEBUG_EVENT debugevent, HANDLE process_handle, char* Symbolbuffer, LPVOID addr)
{
	//解析指针
	//addr = char*addr;
	
	//接受符号的结构体
	CHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	DWORD64 dwDisplacement = 0;
	//根据地址获取符号名
	if (!SymFromAddr(process_handle, (SIZE_T)addr, &dwDisplacement, pSymbol))
	{
		//printf("获取失败\n");
		return FALSE;
	}
	else
	{
		pSymbol->Name;
		sprintf(Symbolbuffer, "%s", pSymbol->Name);
		return TRUE;
	}
	return TRUE;
}

//通过符号获取地址
BOOL BreakPoint::GetSymBolFromName(DEBUG_EVENT debugevent, HANDLE process_handle,CHAR * Name)
{
	CHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	DWORD64 dwDisplacement = 0;

	if (!SymFromName(process_handle, Name, pSymbol))
	{
		printf("获取失败\n");
		return FALSE;
	}
	else
	{
		printf("%x\n", pSymbol->Address);
	}
	return TRUE;
}

//dump
void BreakPoint::Dump(HANDLE hProcess)
{
	LPCSTR str = "dump.exe";
	HANDLE hFile = CreateFile(str, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(0, "创建失败", 0, 0);
		if (GetLastError() == 0x00000050) {
			MessageBox(0, "文件已存在", 0, 0);
		}
		return;
	}
	IMAGE_DOS_HEADER dos;//dos头

	IMAGE_NT_HEADERS nt;
	//读dos头
	LPVOID imgBase = (LPVOID)0x400000;
	//HANDLE Hprocess = m_tpInfo.hProcess;
	HANDLE Hprocess = hProcess;
	if (ReadProcessMemory(Hprocess,
		(BYTE*)imgBase, &dos, sizeof(IMAGE_DOS_HEADER), NULL) == FALSE)
		return;


	//读nt头
	if (ReadProcessMemory(Hprocess, (BYTE*)imgBase + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL) == FALSE)
	{
		return;
	}


	//读取区块并计算区块大小
	DWORD secNum = nt.FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Sections = new IMAGE_SECTION_HEADER[secNum];
	//读取区块
	if (ReadProcessMemory(Hprocess,
		(BYTE*)imgBase + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS),
		Sections,
		secNum * sizeof(IMAGE_SECTION_HEADER),
		NULL) == FALSE)
	{
		return;
	}

	//计算所有区块的大小
	DWORD allsecSize = 0;
	DWORD maxSec;//最大的区块

	maxSec = 0;

	for (int i = 0; i < secNum; ++i)
	{
		allsecSize += Sections[i].SizeOfRawData;

	}

	//区块总大小
	DWORD topsize = secNum * sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_NT_HEADERS) + dos.e_lfanew;

	//使头大小按照文件对齐
	if ((topsize & nt.OptionalHeader.FileAlignment) != topsize)
	{
		topsize &= nt.OptionalHeader.FileAlignment;
		topsize += nt.OptionalHeader.FileAlignment;
	}

	DWORD ftsize = topsize + allsecSize;
	//创建文件映射
	HANDLE hMap = CreateFileMapping(hFile,
		NULL, PAGE_READWRITE,
		0,
		ftsize,
		0);

	if (hMap == NULL)
	{
		printf("创建文件映射失败\n");
		return;
	}

	//创建视图
	LPVOID lpmem = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

	if (lpmem == NULL)
	{
		delete[] Sections;
		CloseHandle(hMap);
		printf("创建失败\n");
		return;
	}
	PBYTE bpMem = (PBYTE)lpmem;
	memcpy(lpmem, &dos, sizeof(IMAGE_DOS_HEADER));
	//计算dossub 大小

	DWORD subSize = dos.e_lfanew - sizeof(IMAGE_DOS_HEADER);

	if (ReadProcessMemory(Hprocess, (BYTE*)imgBase + sizeof(IMAGE_DOS_HEADER), bpMem + sizeof(IMAGE_DOS_HEADER), subSize, NULL) == FALSE)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		return;
	}

	nt.OptionalHeader.ImageBase = (DWORD)imgBase;
	//保存NT头
	memcpy(bpMem + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS));

	//保存区块
	memcpy(bpMem + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS), Sections, secNum * sizeof(IMAGE_SECTION_HEADER));

	for (int i = 0; i < secNum; ++i)
	{
		if (ReadProcessMemory(
			Hprocess, (BYTE*)imgBase + Sections[i].VirtualAddress,
			bpMem + Sections[i].PointerToRawData,
			Sections[i].SizeOfRawData,
			NULL) == FALSE)
		{
			delete[] Sections;
			CloseHandle(hMap);
			UnmapViewOfFile(lpmem);
			return;
		}
	}
	if (FlushViewOfFile(lpmem, 0) == false)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		printf("保存到文件失败\n");
		return;
	}
	delete[] Sections;
	CloseHandle(hMap);
	UnmapViewOfFile(lpmem);
	MessageBox(0, "dump成功", 0, 0);
	return;
}