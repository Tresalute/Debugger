#pragma once
#include <windows.h>


class Tools
{
public:
	Tools();
	~Tools();
	//远程线程注入
	static BOOL HookTool(DEBUG_EVENT debug_event,DWORD process_PID);
	// 远程线程注入
	//static BOOL HookTool(HANDLE hProcess);
	
	
	//寻找并添加插件
	static BOOL addPlugins();
};

