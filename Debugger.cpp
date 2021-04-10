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

//�Ƿ�������� FALSE ���� 
//TREU ������
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


//����PEB
BOOL HideDebugger(HANDLE process_handle)
{
	typedef struct

	{
		DWORD ExitStatus;					// ���ս�����ֹ״̬

		DWORD PebBaseAddress;				// ���ս��̻������ַ

		DWORD AffinityMask;					// ���ս��̹�������

		DWORD BasePriority;					// ���ս��̵����ȼ���

		ULONG UniqueProcessId;				// ���ս���ID

		ULONG InheritedFromUniqueProcessId; //���ո�����ID

	} PROCESS_BASIC_INFORMATION;


	//������������Ϣ ��Ҫ�ǻ��PEB
	PROCESS_BASIC_INFORMATION processinfo = { 0 };

	//���PEB��Ŀ����̵�λ��	��ȡ�ṹ��
	NtQueryInformationProcess(
		process_handle,						//Ŀ����̾��
		ProcessBasicInformation,
		&processinfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL);

	DWORD dwTmp = 0;
	DWORD old_protect = 0;
	//��Ŀ�� begingdebugger λ��д��գ�0��

	BOOL RES = WriteProcessMemory(process_handle, (LPVOID)(processinfo.PebBaseAddress + 0x02), "", 1, &dwTmp);
	   
	return TRUE;
}

void Debugger::Open(LPCTSTR file_path,BOOL bChooice)
{
	//���̴����ɹ������ڽ��ܽ�����Ϣ�� ���� ID 
	PROCESS_INFORMATION process_info = { 0 };
	STARTUPINFO startup_info = { sizeof(STARTUPINFO) };

	//���Է�ʽ��������  
	//�Խ� �� �Ե���״̬�����Ľ��� ����ͨ�� WaitForDebugEvent()���ܵ�
	BOOL result = CreateProcess(file_path, nullptr, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL, NULL, &startup_info, &process_info);

	// DEBUG_PROCESS ��ʾ�Ե��Եķ�ʽ��Ŀ����̣�����
	//	�������Դ����µĽ���ʱ��ͬ�������½��̵ĵ�����Ϣ��
	// DEBUG_ONLY_THIS_PROCESS ֻ����Ŀ����̣�������
	//	Ŀ����̴������µĽ���
	// CREATE_NEW_CONSOLE ��ʾ�´����� CUI �����ʹ��һ
	//	�������Ŀ���̨���У������д�ͺ͵��������ÿ���̨

	//������̴����ɹ��� �͹رն�Ӧ�ľ���� ��ֹ���й¶

	if (result)
	{		
			//HANDLE hThread =  CreateThread(NULL, NULL,
			//(LPTHREAD_START_ROUTINE)(Tools::HookTool),
			//(LPVOID)process_info.dwProcessId, NULL, NULL);

		//��������˲����ִ��HOOK
			if (bChooice)
			{
				HMODULE hModule = LoadLibraryW(PLUGIN_PATH);
				HookTools DllFun = (HookTools)GetProcAddress(hModule, "HookTools");
				if (hModule)
				{
					MessageBox(0, "������سɹ�", 0, 0);
				}
				else
				{
					MessageBox(0, "�������ʧ��", 0, 0);
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

//���ܲ���������¼�
void Debugger::Run()
{


	//ͨ��ѭ�����ϵĴӵ��Զ����л�ȡ������Ϣ
	LPVOID startaddr = 0;
	while (WaitForDebugEvent(&debug_event,INFINITE))
	{
		// open process and theread
		

		//�޸�begingdebugger
		static bool bTmpButton = true;
		if (bTmpButton)
		{			
			//��ʼ�������ļ�
			OpenHandles();
			bTmpButton = false;
		}

		//forever breakpoint
		// dwDebugEventCode ��ʾ��ǰ���ܵ����¼�����
		switch (debug_event.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:     // �쳣�����¼�
		{
			static bool disposableButton = true;
			if (disposableButton)
			{
				//PROCESS_INFORMATION process_info = { 0 };
				//STARTUPINFO startup_info = { sizeof(STARTUPINFO) };
				//CreateProcess("ע�����.exe", nullptr, NULL, NULL, FALSE,
				//	HIGH_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
				//	NULL, NULL, &startup_info, &process_info);
				Tools::HookTool(debug_event,debug_event.dwProcessId);

				disposableButton = false;
			}

			OnExceptionEvent(); break;
		}
			//case CREATE_THREAD_DEBUG_EVENT: // �̴߳����¼�
			////Tools::HookTool(process_handle);
 			//printf("CREATE_THREAD_DEBUG_EVENT\n"); break;
 		case CREATE_PROCESS_DEBUG_EVENT:// ���̴����¼�
			BreakPoint::SetCcBreakPoint(process_handle, debug_event.u.CreateProcessInfo.lpStartAddress);
			BreakPoint::HideDebugger(process_handle);
			//CreateThread(NULL, NULL,
			//	(LPTHREAD_START_ROUTINE)(Tools::HookTool),
			//	(LPVOID)debug_event.dwProcessId, NULL, NULL);
			break;
 		case EXIT_THREAD_DEBUG_EVENT:   // �˳��߳��¼�
 			printf("EXIT_THREAD_DEBUG_EVENT\n"); break;
 		case EXIT_PROCESS_DEBUG_EVENT:  // �˳������¼�
			system("pause");
 			printf("EXIT_PROCESS_DEBUG_EVENT\n"); break;
 		case LOAD_DLL_DEBUG_EVENT:      // ӳ��DLL�¼�
			BreakPoint::InitalSymbol(debug_event, process_handle);
 			printf("LOAD_DLL_DEBUG_EVENT\n"); break;
 		case UNLOAD_DLL_DEBUG_EVENT:    // ж��DLL�¼� 
 			printf("UNLOAD_DLL_DEBUG_EVENT\n"); break;
 		case OUTPUT_DEBUG_STRING_EVENT: // ��������¼�
 			printf("OUTPUT_DEBUG_STRING_EVENT\n"); break;
 		case RIP_EVENT:                 // RIP�¼�(�ڲ�����)
 			printf("RIP_EVENT\n"); break;
		}
		// �ڴ���ģ������¼��ͽ��̴����¼���ʱ�򣬶�Ӧ�Ľṹ��
		// �л��ṩ�����ֶΣ�lpImageName �� fUnicode��������
		// lpImageName ��һ��ָ��Ŀ������ڴ�ռ�ָ�룬��ַ��
		// ������ģ������ƣ�fUnicode���ڱ�ʶ�����Ƿ��ǿ��ַ���
		// ���ǣ�ʵ����������ֵû���κε����塣����ͨ����������
		// ����ͨ���ļ�����ҵ�ģ������(·��)��ȡ��

		// To prevent handle disclose that  close it
		//CloseHandles();
		
		// �������ϵͳ���ص�ǰ�Ĵ�����: �����еĽ��� id  ��
		// �߳� id ������ͨ�� WaitForDebugEvent ��ȡ���� id��
		// ��Ϊ�����ԵĿ����Ƕ�������еĶ���̣߳���Ҫ�������֡�
		// �������Ǵ�����������ɹ��˾�Ӧ�÷��� DBG_CONTINUE��
		// ���账��ʧ�ܣ�����û�д����Ӧ�÷��� DBG_EXCEPTION_NOT_HANDLED 
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
		// �ڴ�����쳣 
	case EXCEPTION_ACCESS_VIOLATION:
	{
		//�޸��ϵ� ��� ��ַ�Բ��� ���޸������һ�������ϵ�
		//��ַ��������ɾ���ڴ�ϵ� �����������һ��ָ��
		//�޸��ĸı��˱������ڴ�ҳ ������ָ��ĵ�ַ
		LPVOID memexception_addr = (LPVOID)debug_event.u.Exception.ExceptionRecord.ExceptionInformation[1];
		ULONG_PTR errotype = debug_event.u.Exception.ExceptionRecord.ExceptionInformation[0];
		BOOL res = FALSE;

		

		switch (errotype)
		{
		case 0x00://read ��
			res = BreakPoint::RepairMemBreakPoint(process_handle, thread_handle, memexception_addr,TRUE);
			break;
		case 0x01://wirte д
			res = BreakPoint::RepairMemBreakPoint(process_handle, thread_handle, memexception_addr, TRUE);
			break;
		case 0x08://execute ִ��
			res = BreakPoint::RepairMemBreakPoint(process_handle, thread_handle, addr, TRUE);
			break;
		default:
			break;
		}
		if (res)
		{
			//�޸��������һ��ָ�� ���ص�����
			bGetCommand = FALSE;
			button = nullbutton;
			break;
		}
		else 
		{
			//û�޸�����ָ�����
			bGetCommand = TRUE;
			break;	
		}
	}
	//braekpoint exception ; int3 can be trigger
	//INT3 �ϵ� ����
	case EXCEPTION_BREAKPOINT:
		// �����̱�������ʱ�򣬲���ϵͳ���⵱ǰ��
		// �����Ƿ��ڱ�����״̬������������ˣ���
		// ��ͨ�� int 3 ����һ������ϵ㣬����ϵ�
		// ͨ������Ҫ����
	{
		//�޸�INT3
		BreakPoint::FixCcBreakPoint(process_handle, thread_handle, addr);
		bGetCommand = FALSE;
		if (button == bpButton)
		{
			//����һ����ַ����TP�ϵ�
			BreakPoint::SetTfBreakPoint(thread_handle);
		}


		//�����ϵ�
		if (codButton)
		{
			BOOL res = BreakPoint::ConditionBreakPoint(process_handle,	//���̾��
				thread_handle,			//�߳̾��
				conditionbp.addr,		//�ϵ㴦
				conditionbp.registers,	//��Ҫ�޸ĵļĴ���
				conditionbp.value);		//��Ҫ�޸ĵļĴ���ֵ
			if (res)
			{	//�ҵ���Ӧ������رտ���
				//ɾ��vector�еĶ�Ӧ��ַ ConditionBreakPoint �н�����ɾ��
				//��������
				codButton = FALSE;
				button = nullbutton;
				bGetCommand = FALSE;
				break;
			}
			else
			{
				//û�ҵ� ������һ��INT3
				//����������
				//BreakPoint::SetCcBreakPoint(process_handle, conditionbp.addr);
				return;
			}
		}
		break;
	}

		//�����ϵ�
		//��������
	case EXCEPTION_SINGLE_STEP:
	{
		//repair breakpoint
		//BreakPoint::ResBreakpoint(thread_handle);

		BOOL res = FALSE;
		BOOL ccRes = FALSE;

		//���ÿ��� ���и����ͲŻῪ����Ӧ����
		//Ȼ��ִ�ж�Ӧ�Ĳ���
		
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
		//��ȡ����
		printf(">>");
		scanf_s("%s", input, 0x100);

		//ִ��
		if (!strcmp(input,"g"))
		{
			//ִ�г��� ֱ�������쳣
			break;
		}
		else if (!strcmp(input,"u"))
		{
			// �鿴ָ��location �� ָ�����code
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
			printf("�Ƿ��������öϵ� Y/N :");
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
				printf("ָ�����\n");
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
				printf("ָ���������\n");
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
				printf("ָ���������\n");
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

			//����һ��������INT3�ϵ�
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
			printf("g\t\t\tִ��\n");
			printf("u\t\t\t��ʾָ����ַ����� ����1����ַ ����2����ʾ����\n");
			printf("p\t\t\t�������� \n");
			printf("o\t\t\t�������� \n");
			printf("bp\t\t\tINT3�ϵ� ����1����ַ\n");
			printf("hbp\t\t\tӲ���ϵ� ����1����ַ ����2��ģʽ��r,w,e��\n");
			printf("mbp\t\t\tӲ���ϵ� ����1����ַ ����2��ģʽ��r,w,e��\n");
			printf("codbp\t\t\t�����ϵ㣨�Ĵ����� ����1������\n");
			printf("view_stack\t\t�鿴��ջ\n");
			printf("view_mem\t\t�鿴ָ���ڴ�HEX ����1����ַ ����2 ��ʾ����\n");
			printf("view_reg\t\t�鿴�Ĵ�����Ϣ\n");
			printf("view_mod\t\t�鿴��ջ��Ϣ\n");
			printf("view_tables\t\t�鿴�����������Ϣ\n");
			printf("modify_cpl\t\t�޸Ļ����� ����1����ַ ����2��������\n");
			printf("modify_mem\t\t�޸��ڴ� ����1����ַ ����2:16�����ڴ�\n");
			printf("modify_reg\t\t�޸ļĴ��� ����1���Ĵ��� ����2��ֵ\n");
			printf("================================================================================\n");
		}
		else
		{
			printf("ָ���������\n");
		}
	} 
}

