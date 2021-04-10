#include "Tools.h"

#define DLL_PATH L"D:\\paper\\My_Debugger\\demo debugger\\NtQueryInformationProcess_Hook.dll"


Tools::Tools()
{
}


Tools::~Tools()
{
}

// 远程线程注入
BOOL Tools::HookTool(DEBUG_EVENT debug_event,DWORD process_PID)
{


	//char old_opcode[0x05] = { };
	//char new_opcode[0x05] = { 0xE9 };

	////保存前5个字节
	//debug_event.u.CreateProcessInfo.lpStartAddress;
	//memcpy(old_opcode, debug_event.u.CreateProcessInfo.lpStartAddress, 5);

	////获取loadlibrary 地址
	//(DWORD)LoadLibrary;
	////转换为地址偏移
	//DWORD offset = (DWORD)debug_event.u.CreateProcessInfo.lpStartAddress - (DWORD)LoadLibrary - 5;
	////构建ShellCode
	//new_opcode;
	//*(DWORD*)(new_opcode + 1) = offset;
	////替换前5个字节
	//memcpy(debug_event.u.CreateProcessInfo.lpStartAddress, new_opcode,5);



	//待注入进程ID 正常情况下 遍历获得
	DWORD dwId = process_PID;

	//1.打开进程，得到目标句柄
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwId);

	//2.在目标内存申请一块能存放文件路径的控件
	DWORD dwSize = (wcslen(DLL_PATH) + 1) * 2;
	LPVOID lpAddress = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);

	//3.将DLL文件的路径写入目标进程
	SIZE_T szSize = 0;
	WriteProcessMemory(hProcess, lpAddress, DLL_PATH, dwSize, &szSize);

	//4.在目标路径创建一个线程
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,
		(LPTHREAD_START_ROUTINE)LoadLibrary,
		lpAddress, NULL, NULL);

	ResumeThread(hThread);
	

	//5.等待线程结束
	//WaitForSingleObject(hThread, -1);
	//VirtualFreeEx(hProcess, lpAddress, dwSize, NULL);

	//6 程序结束
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}

//// 远程线程注入
//BOOL Tools::HookTool(HANDLE hProcess)
//{
//	//待注入进程ID 正常情况下 遍历获得
//
//	//1.打开进程，得到目标句柄
//
//	//2.在目标内存申请一块能存放文件路径的控件
//	DWORD dwSize = (wcslen(DLL_PATH) + 1) * 2;
//	LPVOID lpAddress = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
//
//	//3.将DLL文件的路径写入目标进程
//	SIZE_T szSize = 0;
//	WriteProcessMemory(hProcess, lpAddress, DLL_PATH, dwSize, &szSize);
//
//	//4.在目标路径创建一个线程
//	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,
//		(LPTHREAD_START_ROUTINE)LoadLibrary,
//		lpAddress, NULL, NULL);
//
//	//5.等待线程结束
//	//WaitForSingleObject(hThread, -1);
//	//VirtualFreeEx(hProcess, lpAddress, dwSize, NULL);
//
//	//6 程序结束
//	CloseHandle(hThread);
//	return TRUE;
//}


//寻找并添加插件
BOOL Tools::addPlugins()
{
	return TRUE;
}
