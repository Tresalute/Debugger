#include "Debugger.h"
#include <stdio.h>
#include "Capstone.h"


// 1. 获取调试权限..（用于附加进程使用）
bool EnableDebugPrivilege()
{
	HANDLE hToken = NULL;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	TOKEN_ELEVATION_TYPE ElevationType;
	DWORD dwSize = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		MessageBoxA(NULL, "打开失败", 0, 0);
		return   FALSE;
	}


	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		MessageBoxA(NULL, "获取失败", 0, 0);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // 选择还是关闭

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		CloseHandle(hToken);
		MessageBoxA(NULL, "获取权限失败", 0, 0);
		return false;
	}
	if (GetTokenInformation(hToken, TokenElevationType, &ElevationType, sizeof(TOKEN_ELEVATION_TYPE), &dwSize))
	{
		// 如果令牌是以受限的权限运行 (TokenElevationTypeLimited) ,
		if (ElevationType == TokenElevationTypeLimited)
		{
			//MessageBox( NULL , L"您必须以管理员身份运行,否则无法获取获取系统的内存使用率" , 0 , 0 );
			return	FALSE;
		}
	}
	return true;
}

int main()
{
	int choice = 0;
	int plugincho0ice = 0;
	Debugger debugger;
	bool bres = EnableDebugPrivilege();
	printf("1.创建调试进程\n");
	printf("2.附加活动进程\n");
	printf(">>");
	scanf_s("%d", &choice);
	printf("是否加载插件\n");
	printf("1 YES\n");
	printf("2.NO\n");
	printf(">>");
	scanf_s("%d", &plugincho0ice);
	BOOL bChoice = FALSE;
	if (plugincho0ice == 1)
	{
		bChoice = TRUE;

	}
	else if (plugincho0ice == 2) {}
	else
	{
		printf("输入错误");
		exit(0);
	}

	if (choice == 1)
	{
		debugger.Open("demo.exe", bChoice);
	}
	else if(choice == 2 )
	{
		int PID = 0;
		printf("请输入PID：");
		scanf("%d", &PID);
		BOOL res = DebugActiveProcess(PID);
		if (res)
		{
			Capstone::Init();
		}
		else
		{
			printf("打开进程失败\n");
		}
	}
	else 
	{
		printf("输入错误\n");
		exit(0);
	}
	
	
	debugger.Run();
	return 0;
}