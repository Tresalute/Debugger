#include "Capstone.h"
#include "BreakPoint.h"
csh Capstone::Handle = { 0 };
cs_opt_mem Capstone::OptMem = { 0 };
			
// initialize 
void Capstone::Init()
{
	//����ѿռ�ص�����
	OptMem.calloc = calloc;
	OptMem.free = free;
	OptMem.malloc = malloc;
	OptMem.realloc = realloc;
	OptMem.vsnprintf = vsnprintf;

	//ע��ѿռ�����麯��
	cs_option(NULL, CS_OPT_MEM, (size_t)&OptMem);

	//��һ�����
	cs_open(CS_ARCH_X86, CS_MODE_32, &Capstone::Handle);
}

//�����ָ�����������
void Capstone::DisAsm(DEBUG_EVENT debug_event,HANDLE Handle, LPVOID Addr, DWORD Count)
{
	//������ȡָ��λ���ڴ�Ļ�������Ϣ
	cs_insn* ins = nullptr;
	PCHAR buff = new CHAR[Count * 0x10]{ 0 };

	//ָ����ȡ���ȵ��ڴ�ռ�
	DWORD dwWrite = 0;
	ReadProcessMemory(Handle, Addr, buff, Count * 0x10, &dwWrite);
	//��ȡ ������
	int count = cs_disasm(Capstone::Handle, 
		(uint8_t*)buff, Count * 16, (uint64_t)Addr, 0, &ins);

	//for ��������������»�������⣬������Ҫ�޸�����
	// ĳЩʱ�����öε���������Чָ��
	for (DWORD i = 0;i<Count;++i)
	{
		printf("%08x\t", (UINT)ins[i].address);
		for (uint16_t j = 0; j < 16; j++)
		{
			if (j < ins[i].size)
				printf("%02x", ins[i].bytes[j]);
			else
				printf("  ");
		}
		//�����Ӧ�ķ����
		printf("%s %s", ins[i].mnemonic, ins[i].op_str);
		//�������
		if (!strcmp(ins[i].mnemonic, "jmp") || !strcmp(ins[i].mnemonic, "call"))
		{
			char* buffer = nullptr;
			buffer = ins[i].op_str;
			while (*buffer != '0')
			{
				buffer++;
			}
			//buffer += 2;
			char addrbuffer[2000] = { 0 };

			DWORD64 dwAddr = -0;
			memcpy(buffer + 10, "", 1);
			//sscanf_s(ins[i].op_str, "%08x", &dwAddr);
			sscanf_s(buffer, "%010x", &dwAddr);
			BreakPoint::GetSymbolFromAddr(debug_event, Handle, addrbuffer, (LPVOID)dwAddr);
			printf("\t%s\n", addrbuffer);
		}
		else
			printf("\n");
	}
	printf("\n");
	//�ͷŶ�̬�ڴ����Ŀռ�
	delete[] buff;
	cs_free(ins, count);
}

//return order lenth
int Capstone::ReOrderLenth(HANDLE Handle, LPVOID Addr)
{
	//������ȡָ��λ���ڴ�Ļ�������Ϣ
	cs_insn* ins = nullptr;
	PCHAR buff = new CHAR[0x10]{ 0 };

	//ָ����ȡ���ȵ��ڴ�ռ�
	DWORD dwWrite = 0;
	ReadProcessMemory(Handle, Addr, buff, 0x10, &dwWrite);
	//��ȡ ������
	int count = cs_disasm(Capstone::Handle,
		(uint8_t*)buff, 0x10, (uint64_t)Addr, 0, &ins);
	return ins->size;
}





