#include "Tools.h"

#define DLL_PATH L"D:\\paper\\My_Debugger\\demo debugger\\NtQueryInformationProcess_Hook.dll"


Tools::Tools()
{
}


Tools::~Tools()
{
}

// Զ���߳�ע��
BOOL Tools::HookTool(DEBUG_EVENT debug_event,DWORD process_PID)
{


	//char old_opcode[0x05] = { };
	//char new_opcode[0x05] = { 0xE9 };

	////����ǰ5���ֽ�
	//debug_event.u.CreateProcessInfo.lpStartAddress;
	//memcpy(old_opcode, debug_event.u.CreateProcessInfo.lpStartAddress, 5);

	////��ȡloadlibrary ��ַ
	//(DWORD)LoadLibrary;
	////ת��Ϊ��ַƫ��
	//DWORD offset = (DWORD)debug_event.u.CreateProcessInfo.lpStartAddress - (DWORD)LoadLibrary - 5;
	////����ShellCode
	//new_opcode;
	//*(DWORD*)(new_opcode + 1) = offset;
	////�滻ǰ5���ֽ�
	//memcpy(debug_event.u.CreateProcessInfo.lpStartAddress, new_opcode,5);



	//��ע�����ID ��������� �������
	DWORD dwId = process_PID;

	//1.�򿪽��̣��õ�Ŀ����
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwId);

	//2.��Ŀ���ڴ�����һ���ܴ���ļ�·���Ŀؼ�
	DWORD dwSize = (wcslen(DLL_PATH) + 1) * 2;
	LPVOID lpAddress = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);

	//3.��DLL�ļ���·��д��Ŀ�����
	SIZE_T szSize = 0;
	WriteProcessMemory(hProcess, lpAddress, DLL_PATH, dwSize, &szSize);

	//4.��Ŀ��·������һ���߳�
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,
		(LPTHREAD_START_ROUTINE)LoadLibrary,
		lpAddress, NULL, NULL);

	ResumeThread(hThread);
	

	//5.�ȴ��߳̽���
	//WaitForSingleObject(hThread, -1);
	//VirtualFreeEx(hProcess, lpAddress, dwSize, NULL);

	//6 �������
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}

//// Զ���߳�ע��
//BOOL Tools::HookTool(HANDLE hProcess)
//{
//	//��ע�����ID ��������� �������
//
//	//1.�򿪽��̣��õ�Ŀ����
//
//	//2.��Ŀ���ڴ�����һ���ܴ���ļ�·���Ŀؼ�
//	DWORD dwSize = (wcslen(DLL_PATH) + 1) * 2;
//	LPVOID lpAddress = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
//
//	//3.��DLL�ļ���·��д��Ŀ�����
//	SIZE_T szSize = 0;
//	WriteProcessMemory(hProcess, lpAddress, DLL_PATH, dwSize, &szSize);
//
//	//4.��Ŀ��·������һ���߳�
//	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,
//		(LPTHREAD_START_ROUTINE)LoadLibrary,
//		lpAddress, NULL, NULL);
//
//	//5.�ȴ��߳̽���
//	//WaitForSingleObject(hThread, -1);
//	//VirtualFreeEx(hProcess, lpAddress, dwSize, NULL);
//
//	//6 �������
//	CloseHandle(hThread);
//	return TRUE;
//}


//Ѱ�Ҳ���Ӳ��
BOOL Tools::addPlugins()
{
	return TRUE;
}
