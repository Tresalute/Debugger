#pragma once
//PE 类
#include <windows.h>
class MyPe
{
public:
	MyPe(IN LPCWSTR lpFileName);
	~MyPe();

	DWORD RVA2FOA(DWORD RVA);

	DWORD readPefile(IN LPCWSTR lpFileName);
	DWORD filebuffertoimagebuffer();
	PIMAGE_DOS_HEADER GetDosHeader();
	PIMAGE_NT_HEADERS GetNtHeader();
	PIMAGE_FILE_HEADER GetFileHeader();
	PIMAGE_OPTIONAL_HEADER GetOptionalHeader();
	PIMAGE_SECTION_HEADER GetSectionHeader();
	PIMAGE_EXPORT_DIRECTORY GetExportTable();
	PIMAGE_IMPORT_DESCRIPTOR GetImportTable();
	PIMAGE_RESOURCE_DIRECTORY GetResourceTable(DWORD dwResourceTableRva);
	PIMAGE_BASE_RELOCATION GetReLocalTAble();
	PIMAGE_TLS_DIRECTORY GetTlsTable();
	PIMAGE_DELAYLOAD_DESCRIPTOR GetDelayLoadTable();
	CHAR* FileBufferToImageBuffer();
	BOOL ChangeImportTable();
	//头
	DWORD m_dwFileSize;
	char* m_buf = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr;
	PIMAGE_NT_HEADERS pNtHeader = nullptr;
	PIMAGE_FILE_HEADER pFileHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = nullptr;
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr;
	//表
	PIMAGE_EXPORT_DIRECTORY pExportTable = nullptr;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = nullptr;
	PIMAGE_RESOURCE_DIRECTORY pResourceTables = nullptr;
	PIMAGE_BASE_RELOCATION pReLocalTables = nullptr;
	PIMAGE_TLS_DIRECTORY pTLSTables = nullptr;
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayLoad = nullptr;

	char resourceType[0x10][0x10] = {
		"鼠标资源",
		"位图",
		"图标",
		"菜单",
		"对话框",
		"字符目录",
		"字体",
		"快捷键",
		"非格式化",
		"消息列表",
		"鼠标指正数组",
		"图标组",
		"版本信息"
	};
};
//数字转16进制字符
//WCHAR* DwToWchar(DWORD dwNum, int radix);