#pragma once
#include <windows.h>

//�洢�����ϵ�Ľṹ��
typedef struct _CONDITIONBP
{
	LPVOID addr = 0;
	char registers[0x10] = { 0 };
	DWORD value = 0;
}CONDITIONBP ,*PCONDITIONBP;

// ��������: ����������ϵͳ��������յ��ĵ�����Ϣ
//	��ȡ�û������룬��������Ӧ�����������
class Debugger
{
private:
	//��������¼��Ľṹ��
	DEBUG_EVENT debug_event = { 0 };
	
	//���洦����
	DWORD ContinueStaus = DBG_CONTINUE;

	// to save handle and thread's id of exception produce
	HANDLE thread_handle = NULL;
	HANDLE process_handle = NULL;

	//�洢�����ϵ�Ľṹ��
	static CONDITIONBP conditionbp;

public:
	//����һ��·�����Ե��Է�ʽ��������
	void Open(LPCTSTR file_path,BOOL bChooice);
	//���ܲ���������¼�
	void Run();

private:
	//�ṩ�������ڴ�Ŀ����̺�Close Handle
	void OpenHandles();
	void CloseHandles();

	//use for dispose of receive  all Exception event;
	void OnExceptionEvent();

	// Get user input
	void Get_command(LPVOID Addr);
	

};

