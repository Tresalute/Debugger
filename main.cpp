#include "Debugger.h"
#include <stdio.h>
#include "Capstone.h"


// 1. ��ȡ����Ȩ��..�����ڸ��ӽ���ʹ�ã�
bool EnableDebugPrivilege()
{
	HANDLE hToken = NULL;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	TOKEN_ELEVATION_TYPE ElevationType;
	DWORD dwSize = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		MessageBoxA(NULL, "��ʧ��", 0, 0);
		return   FALSE;
	}


	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		MessageBoxA(NULL, "��ȡʧ��", 0, 0);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // ѡ���ǹر�

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		CloseHandle(hToken);
		MessageBoxA(NULL, "��ȡȨ��ʧ��", 0, 0);
		return false;
	}
	if (GetTokenInformation(hToken, TokenElevationType, &ElevationType, sizeof(TOKEN_ELEVATION_TYPE), &dwSize))
	{
		// ��������������޵�Ȩ������ (TokenElevationTypeLimited) ,
		if (ElevationType == TokenElevationTypeLimited)
		{
			//MessageBox( NULL , L"�������Թ���Ա�������,�����޷���ȡ��ȡϵͳ���ڴ�ʹ����" , 0 , 0 );
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
	printf("1.�������Խ���\n");
	printf("2.���ӻ����\n");
	printf(">>");
	scanf_s("%d", &choice);
	printf("�Ƿ���ز��\n");
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
		printf("�������");
		exit(0);
	}

	if (choice == 1)
	{
		debugger.Open("demo.exe", bChoice);
	}
	else if(choice == 2 )
	{
		int PID = 0;
		printf("������PID��");
		scanf("%d", &PID);
		BOOL res = DebugActiveProcess(PID);
		if (res)
		{
			Capstone::Init();
		}
		else
		{
			printf("�򿪽���ʧ��\n");
		}
	}
	else 
	{
		printf("�������\n");
		exit(0);
	}
	
	
	debugger.Run();
	return 0;
}