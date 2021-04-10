#include "Debugger.h"
#include "Capstone.h"
#include "BreakPoint.h"
#include "Tools.h"
#include <stdio.h>

#include <Winternl.h>
#pragma comment (lib,"Ntdll.lib")

#include "XEDParse/XEDParse.h"

BOOL membpButton = TRUE;
BOOL ccbpButton = TRUE;
BOOL codButton = FALSE;
BOOL pButton = FALSE;
BOOL memButton = FALSE;

//是否接收输入 FALSE 接收 
//TREU 不接收
BOOL bGetCommand = FALSE;


typedef enum eButton
{
	nullbutton,
	bpButton ,
	hbpButton,
	mbpButton,
};

eButton button;

CONDITIONBP Debugger::conditionbp;

#define DLLPATH L"D:\\paper\\My_Debugger\\demo debugger\\NtQueryInformationProcess_Hook.dll"
#define PLUGIN_PATH L"./Plugin/Plugins.dll"


typedef BOOL(*HookTools)(DWORD process_PID, const wchar_t* Path);


//隐藏PEB
BOOL HideDebugger(HANDLE process_handle)
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

	//获得PEB在目标进程的位置	获取结构体
	NtQueryInformationProcess(
		process_handle,						//目标进程句柄
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

void Debugger::Open(LPCTSTR file_path,BOOL bChooice)
{
	//进程创建成功，用于接受进程信息与 进程 ID 
	PROCESS_INFORMATION process_info = { 0 };
	STARTUPINFO startup_info = { sizeof(STARTUPINFO) };

	//调试方式创建进程  
	//自解 ： 以调试状态创建的进程 可以通过 WaitForDebugEvent()接受到
	BOOL result = CreateProcess(file_path, nullptr, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL, NULL, &startup_info, &process_info);

	// DEBUG_PROCESS 表示以调试的方式打开目标进程，并且
	//	当被调试创建新的进程时，同样接收新进程的调试信息。
	// DEBUG_ONLY_THIS_PROCESS 只调试目标进程，不调试
	//	目标进程创建的新的进程
	// CREATE_NEW_CONSOLE 表示新创建的 CUI 程序会使用一
	//	个独立的控制台运行，如果不写就和调试器共用控制台

	//如果进程创建成功， 就关闭对应的句柄， 防止句柄泄露

	if (result)
	{		
			//HANDLE hThread =  CreateThread(NULL, NULL,
			//(LPTHREAD_START_ROUTINE)(Tools::HookTool),
			//(LPVOID)process_info.dwProcessId, NULL, NULL);

		//如果加载了插件便执行HOOK
			if (bChooice)
			{
				HMODULE hModule = LoadLibraryW(PLUGIN_PATH);
				HookTools DllFun = (HookTools)GetProcAddress(hModule, "HookTools");
				if (hModule)
				{
					MessageBox(0, "插件加载成功", 0, 0);
				}
				else
				{
					MessageBox(0, "插件加载失败", 0, 0);
				}
				//DllFun(process_info.dwProcessId, DLLPATH);
				HANDLE hThread = CreateThread(NULL, NULL,
					(LPTHREAD_START_ROUTINE)DllFun,
					(LPVOID)process_info.dwProcessId,
					NULL, NULL);

				SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
			}

		CloseHandle(process_info.hProcess);
		CloseHandle(process_info.hThread);
	}
	Capstone::Init();
}

//接受并处理调试事件
void Debugger::Run()
{


	//通过循环不断的从调试对象中获取调试信息
	LPVOID startaddr = 0;
	while (WaitForDebugEvent(&debug_event,INFINITE))
	{
		// open process and theread
		

		//修改begingdebugger
		static bool bTmpButton = true;
		if (bTmpButton)
		{			
			//初始化符号文件
			OpenHandles();
			bTmpButton = false;
		}

		//forever breakpoint
		// dwDebugEventCode 表示当前接受到的事件类型
		switch (debug_event.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:     // 异常调试事件
		{
			static bool disposableButton = true;
			if (disposableButton)
			{
				//PROCESS_INFORMATION process_info = { 0 };
				//STARTUPINFO startup_info = { sizeof(STARTUPINFO) };
				//CreateProcess("注入程序.exe", nullptr, NULL, NULL, FALSE,
				//	HIGH_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
				//	NULL, NULL, &startup_info, &process_info);
				Tools::HookTool(debug_event,debug_event.dwProcessId);

				disposableButton = false;
			}

			OnExceptionEvent(); break;
		}
			//case CREATE_THREAD_DEBUG_EVENT: // 线程创建事件
			////Tools::HookTool(process_handle);
 			//printf("CREATE_THREAD_DEBUG_EVENT\n"); break;
 		case CREATE_PROCESS_DEBUG_EVENT:// 进程创建事件
			BreakPoint::SetCcBreakPoint(process_handle, debug_event.u.CreateProcessInfo.lpStartAddress);
			BreakPoint::HideDebugger(process_handle);
			//CreateThread(NULL, NULL,
			//	(LPTHREAD_START_ROUTINE)(Tools::HookTool),
			//	(LPVOID)debug_event.dwProcessId, NULL, NULL);
			break;
 		case EXIT_THREAD_DEBUG_EVENT:   // 退出线程事件
 			printf("EXIT_THREAD_DEBUG_EVENT\n"); break;
 		case EXIT_PROCESS_DEBUG_EVENT:  // 退出进程事件
			system("pause");
 			printf("EXIT_PROCESS_DEBUG_EVENT\n"); break;
 		case LOAD_DLL_DEBUG_EVENT:      // 映射DLL事件
			BreakPoint::InitalSymbol(debug_event, process_handle);
 			printf("LOAD_DLL_DEBUG_EVENT\n"); break;
 		case UNLOAD_DLL_DEBUG_EVENT:    // 卸载DLL事件 
 			printf("UNLOAD_DLL_DEBUG_EVENT\n"); break;
 		case OUTPUT_DEBUG_STRING_EVENT: // 调试输出事件
 			printf("OUTPUT_DEBUG_STRING_EVENT\n"); break;
 		case RIP_EVENT:                 // RIP事件(内部错误)
 			printf("RIP_EVENT\n"); break;
		}
		// 在处理模块加载事件和进程创建事件的时候，对应的结构体
		// 中会提供两个字段，lpImageName 和 fUnicode，理论上
		// lpImageName 是一个指向目标进程内存空间指针，地址上
		// 保存了模块的名称，fUnicode用于标识名称是否是宽字符。
		// 但是，实际上这两个值没有任何的意义。可以通过搜索引擎
		// 搜索通过文件句柄找到模块名称(路径)获取。

		// To prevent handle disclose that  close it
		//CloseHandles();
		
		// 向调试子系统返回当前的处理结果: 参数中的进程 id  和
		// 线程 id 必须是通过 WaitForDebugEvent 获取到的 id。
		// 因为被调试的可能是多个进程中的多个线程，需要进行区分。
		// 参数三是处理结果，处理成功了就应该返回 DBG_CONTINUE，
		// 假设处理失败，或者没有处理就应该返回 DBG_EXCEPTION_NOT_HANDLED 
		ContinueDebugEvent(
			debug_event.dwProcessId,
			debug_event.dwThreadId,
			ContinueStaus );
	}
}

//  provide funcation to open and close handle 
void Debugger::OpenHandles()
{
	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
	process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, debug_event.dwProcessId);
}

void Debugger::CloseHandles()
{
	CloseHandle(thread_handle);
	CloseHandle(process_handle);
}


// use to recive exception event and dispose it
void Debugger::OnExceptionEvent()
{
	//Get exception's address and type
	DWORD code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID addr = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;

	//output exception information and produce of address
	printf("Type(%08x):%p\n", code, addr);

	// repair all breakpoint 
	//funcation();
	switch (code)
	{
		// 内存访问异常 
	case EXCEPTION_ACCESS_VIOLATION:
	{
		//修复断点 如果 地址对不上 则修复且添加一个单步断点
		//地址对上了则删除内存断点 且允许接受下一条指令
		//修复的改变了保护的内存页 而不是指令的地址
		LPVOID memexception_addr = (LPVOID)debug_event.u.Exception.ExceptionRecord.ExceptionInformation[1];
		ULONG_PTR errotype = debug_event.u.Exception.ExceptionRecord.ExceptionInformation[0];
		BOOL res = FALSE;

		

		switch (errotype)
		{
		case 0x00://read 读
			res = BreakPoint::RepairMemBreakPoint(process_handle, thread_handle, memexception_addr,TRUE);
			break;
		case 0x01://wirte 写
			res = BreakPoint::RepairMemBreakPoint(process_handle, thread_handle, memexception_addr, TRUE);
			break;
		case 0x08://execute 执行
			res = BreakPoint::RepairMemBreakPoint(process_handle, thread_handle, addr, TRUE);
			break;
		default:
			break;
		}
		if (res)
		{
			//修复后接受下一道指令 并关掉开关
			bGetCommand = FALSE;
			button = nullbutton;
			break;
		}
		else 
		{
			//没修复跳过指令接受
			bGetCommand = TRUE;
			break;	
		}
	}
	//braekpoint exception ; int3 can be trigger
	//INT3 断点 触发
	case EXCEPTION_BREAKPOINT:
		// 当进程被创建的时候，操作系统会检测当前的
		// 进程是否处于被调试状态，如果被调试了，就
		// 会通过 int 3 设置一个软件断点，这个断点
		// 通常不需要处理。
	{
		//修复INT3
		BreakPoint::FixCcBreakPoint(process_handle, thread_handle, addr);
		bGetCommand = FALSE;
		if (button == bpButton)
		{
			//在下一条地址设置TP断点
			BreakPoint::SetTfBreakPoint(thread_handle);
		}


		//条件断点
		if (codButton)
		{
			BOOL res = BreakPoint::ConditionBreakPoint(process_handle,	//进程句柄
				thread_handle,			//线程句柄
				conditionbp.addr,		//断点处
				conditionbp.registers,	//需要修改的寄存器
				conditionbp.value);		//需要修改的寄存器值
			if (res)
			{	//找到对应条件则关闭开关
				//删除vector中的对应地址 ConditionBreakPoint 中进行了删除
				//接受输入
				codButton = FALSE;
				button = nullbutton;
				bGetCommand = FALSE;
				break;
			}
			else
			{
				//没找到 则设置一个INT3
				//不接受输入
				//BreakPoint::SetCcBreakPoint(process_handle, conditionbp.addr);
				return;
			}
		}
		break;
	}

		//单步断点
		//单步步过
	case EXCEPTION_SINGLE_STEP:
	{
		//repair breakpoint
		//BreakPoint::ResBreakpoint(thread_handle);

		BOOL res = FALSE;
		BOOL ccRes = FALSE;

		//设置开关 具有该类型才会开启对应开关
		//然后执行对应的操作
		
		switch (button)
		{
		case bpButton:
		{
			res = BreakPoint::ForeverBreakPoint(process_handle, thread_handle);
			if (res)
				bGetCommand = TRUE;
			else
				bGetCommand = FALSE;
			break;
		}
		case hbpButton:
		{
			BreakPoint::FixHdBreakPoint(thread_handle, addr, TRUE);
			button = nullbutton;
			break;
		}
		case mbpButton:
		{
			BreakPoint::ResMemBreakPoint(process_handle, addr);
			break;
		}
		default:
			break;
		}	
	}
	default:
		break;
	}


	if (bGetCommand)
	{
		return;
	}
	//examine location where eip point, not the abnormal location
	Capstone::DisAsm(debug_event,process_handle, addr, 10);
	Get_command(addr);
	
}

//get user input
void Debugger::Get_command(LPVOID Addr)
{
	char input[0x100] = { 0 };
	while (true)
	{
		//get command
		//获取命令
		printf(">>");
		scanf_s("%s", input, 0x100);

		//执行
		if (!strcmp(input,"g"))
		{
			//执行程序 直到遇到异常
			break;
		}
		else if (!strcmp(input,"u"))
		{
			// 查看指定location 的 指定汇编code
			int addr = 0, lines = 0;
			scanf_s("%x %d", &addr, &lines);
			Capstone::DisAsm(debug_event,process_handle, (LPVOID)addr, lines);
		}
		else if (!strcmp(input, "bp"))
		{
			// set breakpoint
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			getchar();
			printf("是否设置永久断点 Y/N :");
			char choice;
			scanf_s("%c", &choice);

			if (choice == 'Y')
			{
				//ccbpButton = FALSE;	
				button = bpButton;
			}
			else if (choice == 'N')
			{
				//ccbpButton = TRUE;
				button = nullbutton;
			}
			else
			{
				button = nullbutton;
				printf("指令错误\n");
			}
			BreakPoint::SetCcBreakPoint(process_handle, addr);
		}
		else if (!strcmp(input,"hbp"))
		{
			//Set hardware breakpoint 
			LPVOID addr = 0;
			int type = 0;
			int len = 0;
			char mode;
			scanf_s("%x ", &addr);
			scanf_s("%c", &mode);
			getchar();
			len = 3;
			switch (mode)
			{
			case 'e':
				type = 0;
				len = 0;
				break;
			case 'w':
				type = 1;
				break;
			case 'p':
				type = 2;
				break;
			case 'r':
				type = 3;
				break;
			default:
				printf("指令输入错误\n");
				break;
			}
			BreakPoint::SetHdBreakPoint(thread_handle,addr, type, len);
			button = hbpButton;
		}
		else if (!strcmp(input, "mbp"))
		{
			//Set membreakpoint
			LPVOID addr = 0;
			char mode ;
			int type = 0;
			scanf_s("%x ", &addr);
			scanf_s("%c", &mode);
			getchar();	
			switch (mode)
			{
			case 'e':
				type = PAGE_READWRITE;
				break;
			case 'r':
				type = PAGE_NOACCESS;
				break;
			case 'w':
				type = PAGE_EXECUTE_READ;
				break;
			default:
				printf("指令输入错误\n");
				break;
			}
			BreakPoint::SetMemBreakPoint(process_handle, addr, type);
			button = mbpButton;
		}
		else if (!strcmp(input, "o"))
		{
			//Set single step out
			BreakPoint::SetToBreakPoint(process_handle, thread_handle, Addr);
			break;
		}
		else if (!strcmp(input, "p"))
		{
			// set single step in
			pButton = TRUE;
			BreakPoint::SetTfBreakPoint(thread_handle);
			break;
		}
		else if (!strcmp(input, "view_stack"))
		{
			BreakPoint::ViewStack(process_handle, thread_handle);
		}
		else if (!strcmp(input, "view_mem"))
		{
			LPVOID addr = 0;
			INT count = 0;
			int x = 0;
			scanf_s("%x %d", &addr,&count);
			BreakPoint::ViewMem(process_handle, addr, count);
		}
		else if (!strcmp(input, "view_reg"))
		{
			BreakPoint::ViewReg(thread_handle);
		}
		else if (!strcmp(input, "view_mod"))
		{
			BreakPoint::ViewModule(debug_event);
		}
		else if (!strcmp(input, "view_mod_table"))
		{
			char dllName[0x20] = { 0 };
			scanf_s("%s ", dllName);

		}
		else if (!strcmp(input, "modify_mem"))
		{
			LPVOID addr = 0;
			char changeaddr[0x10] = { 0 };
			scanf_s("%x ", &addr);
			scanf_s("%x", changeaddr, 0x10);
			BreakPoint::ModifyMem(process_handle, addr, changeaddr);
		}
		else if (!strcmp(input, "modify_reg"))
		{
			char registers[0x10] = { 0 };
			DWORD value = 0;
			scanf_s("%s ", registers,0x10);
			scanf_s("%x", &value);
			BreakPoint::ModifyRegister(thread_handle, registers, value);
		}
		else if (!strcmp(input, "modify_cpl"))
		{
			LPVOID addr = 0;
			char complation[0x20] = { 0 };
			scanf_s("%x", &addr);
			gets_s(complation, 0x20);
			BreakPoint::ModifyCompilation(process_handle, addr, complation);
		}
		else if (!strcmp(input, "codbp"))
		{
			LPVOID addr = 0;
			char registers[0x10] = { 0 };
			DWORD value = 0;
			scanf_s("%x", &addr);
			scanf_s("%s ", registers, 0x10);
			scanf_s("%x", &value);

			strcpy_s(conditionbp.registers, 0x10, registers);
			conditionbp.value = value;
			conditionbp.addr = addr;

			//设置一个永久性INT3断点
			button = bpButton;
			BreakPoint::SetCcBreakPoint(process_handle, addr);
			codButton = TRUE;
		}
		else if (!strcmp(input, "view_tables"))
		{
			char modulepath[MAX_PATH] = { 0 };
			scanf_s("%s", modulepath, MAX_PATH);
			BreakPoint::GetTables(debug_event, modulepath);
		}
		else if (!strcmp(input, "view_Symbol"))
		{
			LPVOID addr = 0;
			char Symbol[2000] = { 0 };
			scanf_s("%x", &addr);
			BreakPoint::GetSymbolFromAddr(debug_event, process_handle, Symbol, addr);
			printf("%s\n", Symbol);
		}
		else if (!strcmp(input, "dump"))
		{
			BreakPoint::Dump(process_handle);
		}
		else if (!strcmp(input, "help"))
		{
			printf("================================================================================\n");
			printf("g\t\t\t执行\n");
			printf("u\t\t\t显示指定地址反汇编 参数1：地址 参数2：显示行数\n");
			printf("p\t\t\t单步步入 \n");
			printf("o\t\t\t单步步过 \n");
			printf("bp\t\t\tINT3断点 参数1：地址\n");
			printf("hbp\t\t\t硬件断点 参数1：地址 参数2：模式（r,w,e）\n");
			printf("mbp\t\t\t硬件断点 参数1：地址 参数2：模式（r,w,e）\n");
			printf("codbp\t\t\t条件断点（寄存器） 参数1：条件\n");
			printf("view_stack\t\t查看堆栈\n");
			printf("view_mem\t\t查看指定内存HEX 参数1：地址 参数2 显示行数\n");
			printf("view_reg\t\t查看寄存器信息\n");
			printf("view_mod\t\t查看堆栈信息\n");
			printf("view_tables\t\t查看导出表导入表信息\n");
			printf("modify_cpl\t\t修改汇编代码 参数1：地址 参数2：汇编代码\n");
			printf("modify_mem\t\t修改内存 参数1：地址 参数2:16进制内存\n");
			printf("modify_reg\t\t修改寄存器 参数1：寄存器 参数2：值\n");
			printf("================================================================================\n");
		}
		else
		{
			printf("指令输入错误\n");
		}
	} 
}

