#pragma once
#include <windows.h>


class Tools
{
public:
	Tools();
	~Tools();
	//Զ���߳�ע��
	static BOOL HookTool(DEBUG_EVENT debug_event,DWORD process_PID);
	// Զ���߳�ע��
	//static BOOL HookTool(HANDLE hProcess);
	
	
	//Ѱ�Ҳ���Ӳ��
	static BOOL addPlugins();
};

