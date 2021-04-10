#pragma once
#include <windows.h>
#include <vector>
#include "MyPe.h"
using namespace std;

// breakpoint struct
typedef struct _BREAKPOINTINFO
{
	LPVOID addr = 0;
	BYTE old_opcode = 0;
}BREAKPOINTINFO,*PBREAKPOINTINFO;

//memory information
typedef	struct _MEMORYINFO
{
	LPVOID addr = 0;
	BYTE* memvalue = nullptr;
}MEMORYINFO,*PMEMORYINFO;

// memory breakpoint struct
typedef struct _MEMBREAKPOINTINFO 
{
	LPVOID addr = 0;
	DWORD old_protect = 0;
}MEMBREAKPOINTINFO,*PMEMBREAKPOINTINFO;

typedef struct _HBPINFO
{
	LPVOID addr;
	int type;
	int len;
}HBPINFO,*PHBPINFO;

//Class breakpoint, tools class ,provid support
class BreakPoint
{
private:


	//create a vector to sava all breakepoint information
	static vector<BREAKPOINTINFO> vecBreakpoint;

	// to save memory breakpoint
	static vector<MEMBREAKPOINTINFO> vecMemBreakPoint;

	// to save memory breakpoint
	static PMEMBREAKPOINTINFO membreakpoint;

	// to save hardware breakpoint
	static HBPINFO hbpSturct;
public:

	//set software breakpoint (like int3)
	static void SetCcBreakPoint(HANDLE process_handle, LPVOID addr);

	//repair software breakpoint;
	static void FixCcBreakPoint(HANDLE process_handle, HANDLE therad_handle, LPVOID addr);

	//set single step  in
	//the single step will repair by themself
	static void SetTfBreakPoint(HANDLE thread_handle);

	//set hardware breakpoint(DrN)
	static void SetHdBreakPoint(HANDLE thread_handle,  LPVOID addr, int type, int len);

	//repair hardware beakpoint(Drn)
	static BOOL FixHdBreakPoint(HANDLE thread_handle, LPVOID addr, BOOL bButton);
	static void ResHdBreakPoint(HANDLE thread_handle, LPVOID addr);

	//Set memory access breakpoint
	static void SetMemBreakPoint(HANDLE process_handle, LPVOID addr, int mode);

	//Repair memory access breakpoint
	static BOOL RepairMemBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr,BOOL bButton);

	//Restore memBreakpoint
	static BOOL ResMemBreakPoint(HANDLE thread_handle, LPVOID Addr);

	//Restore breakpoint
	static void ResBreakpoint(HANDLE thread_handle);

	//set single step  out
	static void SetToBreakPoint(HANDLE process_handle,HANDLE thread_handle, LPVOID Addr);

	//view stack
	static void ViewStack(HANDLE process_handle, HANDLE thread_handle);

	//view memory
	static void ViewMem(HANDLE process_handle, LPVOID Addr, INT count = 50);

	//view register
	static void ViewReg(HANDLE thread_handle);

	//view module
	static void ViewModule(DEBUG_EVENT debugevent);

	//modify memory
	static void ModifyMem(HANDLE process_handle, LPVOID addr, char* changeaddr);

	//modify register
	static void ModifyRegister( HANDLE thread_handle, char* registe, DWORD value);

	//modify compilation
	static void ModifyCompilation(HANDLE process_handle, LPVOID addr, char* compilationcode);

	//forever breakpoint
	static BOOL ForeverBreakPoint(HANDLE process_handle, HANDLE thread_handle);

	//条件断点
	static BOOL ConditionBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr, char* condition,int value );

	//隐藏PEB
	static BOOL HideDebugger(HANDLE process_handle);

	//解析导入表 导出表
	static BOOL GetTables(DEBUG_EVENT debugevent,char* dlllName);

	//通过地址获取符号
	static BOOL GetSymbolFromAddr(DEBUG_EVENT debugevent,HANDLE process_handle,char* buffer,LPVOID addr);

	//通过符号获取地址
	static BOOL GetSymBolFromName(DEBUG_EVENT debugevent, HANDLE process_handle, CHAR * Name);

	//初始化符号处理器
	static BOOL InitalSymbol(DEBUG_EVENT debugevent, HANDLE process_handle);

	//dump
	static void Dump(HANDLE hProcess);
};

