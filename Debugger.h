#pragma once
#include <windows.h>

//存储条件断点的结构体
typedef struct _CONDITIONBP
{
	LPVOID addr = 0;
	char registers[0x10] = { 0 };
	DWORD value = 0;
}CONDITIONBP ,*PCONDITIONBP;

// 调试器类: 建立调试子系统，处理接收到的调试信息
//	获取用户的输入，并进行相应的输出反馈。
class Debugger
{
private:
	//保存调试事件的结构体
	DEBUG_EVENT debug_event = { 0 };
	
	//保存处理结果
	DWORD ContinueStaus = DBG_CONTINUE;

	// to save handle and thread's id of exception produce
	HANDLE thread_handle = NULL;
	HANDLE process_handle = NULL;

	//存储条件断点的结构体
	static CONDITIONBP conditionbp;

public:
	//接受一个路径，以调试方式创建进程
	void Open(LPCTSTR file_path,BOOL bChooice);
	//接受并处理调试事件
	void Run();

private:
	//提供函数用于打开目标进程和Close Handle
	void OpenHandles();
	void CloseHandles();

	//use for dispose of receive  all Exception event;
	void OnExceptionEvent();

	// Get user input
	void Get_command(LPVOID Addr);
	

};

