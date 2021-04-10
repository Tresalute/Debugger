#pragma once
#include <windows.h>
#include "Capstone/include/capstone.h"
#pragma comment(lib,"capstone/capstone.lib")
#pragma comment(linker, "/NODEFAULTLIB:\"libcmtd.lib\"")


// ����������ࣨ�����ࣩ����Ҫ������ͨ������ĵ�ַ���ر�
//                     �����汣��Ĵ�����Ϣ�����Զ���
//                     ����ʽ���зḻ��
class Capstone
{
public:
	//�����ڴ��ʼ�����ڴ����ľ��
	static csh Handle;
	static cs_opt_mem OptMem;

	// ����ΪĬ�Ϲ��캯��
	Capstone() = default;
	~Capstone() = default;


	//��ʼ������
	static void Init();

	//����ִ�з����ĺ���
	static void DisAsm(DEBUG_EVENT debug_event,HANDLE Handle, LPVOID Addr, DWORD Count);

	//return order lenth
	static int ReOrderLenth(HANDLE Handle, LPVOID Addr);
};

