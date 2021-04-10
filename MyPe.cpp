#include "MyPe.h"
#include <stdio.h>
#include <wchar.h>



//以下是PE 接口的实现

MyPe::MyPe(IN LPCWSTR lpFileName)
{
	readPefile(lpFileName);
	//DOS
	GetDosHeader();
	//NT
	GetNtHeader();
	//FILE
	GetFileHeader();
	//OPTIONAL
	GetOptionalHeader();
	//SECTION
	GetSectionHeader();
	//EXPORT
	GetExportTable();
	//IMPORT
	GetImportTable();
	//RESOURCE
	if (m_buf != nullptr)
	{
		DWORD dwResourceRVA = pOptionalHeader->DataDirectory[2].VirtualAddress;
		GetResourceTable(dwResourceRVA);
	}
	
	//RELOCAL
	GetReLocalTAble();
	//TLS
	GetTlsTable();
	//DELAY
	GetDelayLoadTable();

}

MyPe::~MyPe()
{
}

DWORD MyPe::readPefile(IN LPCWSTR lpFileName)
{
	DWORD readSize = 0;
	//打开文件
	HANDLE hFile = CreateFileW(lpFileName,
		GENERIC_READ ,
		FILE_SHARE_READ ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("文件打开失败\n");
		return false;
	}
	//获取文件大小
	m_dwFileSize = GetFileSize(hFile, NULL);
	printf("文件大小为:%d KB\n", m_dwFileSize / 1024);

	m_buf = new char[m_dwFileSize];

	//读取文件 
	ReadFile(hFile, m_buf, m_dwFileSize, &readSize, nullptr);
	CloseHandle(hFile);
	return m_dwFileSize;
}

PIMAGE_DOS_HEADER MyPe::GetDosHeader()
{
	if (m_buf == nullptr)
	{
		return PIMAGE_DOS_HEADER();
	}
	pDosHeader = (PIMAGE_DOS_HEADER)m_buf;
	return pDosHeader;
}

PIMAGE_NT_HEADERS MyPe::GetNtHeader()
{
	if (m_buf == nullptr)
	{
		return PIMAGE_NT_HEADERS();
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader->e_lfanew + (DWORD)m_buf);
	return pNtHeader;
}

PIMAGE_FILE_HEADER MyPe::GetFileHeader()
{
	if (m_buf == nullptr)
	{
		return PIMAGE_FILE_HEADER();
	}
	pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
	return pFileHeader;
}

PIMAGE_OPTIONAL_HEADER MyPe::GetOptionalHeader()
{
	if (m_buf == nullptr)
	{
		return PIMAGE_OPTIONAL_HEADER();
	}
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
	return pOptionalHeader;
}

PIMAGE_SECTION_HEADER MyPe::GetSectionHeader()
{
	if (m_buf == nullptr)
	{
		return PIMAGE_SECTION_HEADER();
	}
	pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	return pSectionHeader;
}

PIMAGE_EXPORT_DIRECTORY MyPe::GetExportTable()
{
	if (m_buf == nullptr)
	{
		return PIMAGE_EXPORT_DIRECTORY();
	}
	DWORD FOA = RVA2FOA(pOptionalHeader->DataDirectory[0].VirtualAddress);
	pExportTable = (PIMAGE_EXPORT_DIRECTORY)(FOA + (DWORD)pDosHeader);

	//if (FOA == NULL)
	//{
	//	printf("无导出表\n");
	//	return pExportTable;
	//}
	//printf("Base:%d\n", pExportTable->Base);
	//printf("NumberOfFunctions:%d\n", pExportTable->NumberOfFunctions);
	//printf("NumberOfNames:%d\n", pExportTable->NumberOfNames);
	//printf("地址表			");
	//DWORD FOA2 = RVA2FOA(pExportTable->AddressOfFunctions);
	//DWORD* addTable = (DWORD*)(FOA2 + (DWORD)pDosHeader);
	////for (size_t i = 0; i < pExportTable->NumberOfFunctions; i++)
	////{
	////	printf("%x\n", addTable[i]);
	////}
	//printf("序号表			");
	//DWORD FOA3 = RVA2FOA(pExportTable->AddressOfNameOrdinals);
	//WORD* indexTable = (WORD*)(FOA3 + (DWORD)pDosHeader);
	////for (size_t i = 0; i < pExportTable->NumberOfNames; i++)
	////{
	////	printf("%x\n", indexTable[i]+pExportTable->Base);
	////}
	//printf("函数名\n");
	//DWORD FOA4 = RVA2FOA(pExportTable->AddressOfNames);
	//DWORD* NameTable = (DWORD*)(FOA4 + (DWORD)pDosHeader);
	////for (size_t i = 0; i < pExportTable->NumberOfNames; i++)
	////{
	////	//函数名
	////	DWORD tmpFOA = RVA2FOA(NameTable[i]);
	////	char* Name = (char*)(tmpFOA + (DWORD)pDosHeader);
	////	printf("%s ", Name);
	////	//序号表
	////	printf("%14x ", indexTable[i] + pExportTable->Base);
	////	//地址
	////	printf("%26x \n", addTable[indexTable[i]]);
	////}
	//for (size_t i = 0; i < pExportTable->NumberOfFunctions; i++)
	//{
	//	if (addTable[i] == 0)
	//	{
	//		continue;
	//	}
	//	//函数地址
	//	printf("%x ", addTable[i]);
	//	//函数序号
	//	//函数名
	//	BOOL bButton = TRUE;
	//	for (size_t j = 0; j < pExportTable->NumberOfNames; j++)
	//	{
	//		if (indexTable[j] == i)
	//		{
	//			printf("%x ", indexTable[i] + pExportTable->Base);
	//			DWORD tmpFOA = RVA2FOA(NameTable[i]);
	//			char* Name = (char*)(tmpFOA + (DWORD)pDosHeader);
	//			printf("%s \n", Name);
	//			bButton = FALSE;
	//			break;
	//		}
	//	}
	//	if (bButton)
	//	{
	//		printf("null ");
	//		printf("null \n");
	//	}
	//}
	return pExportTable;
}

PIMAGE_IMPORT_DESCRIPTOR MyPe::GetImportTable()
{
	if (m_buf == nullptr)
	{
		return PIMAGE_IMPORT_DESCRIPTOR();
	}
	DWORD FOA =
		RVA2FOA(pOptionalHeader->DataDirectory[1].VirtualAddress);
	pImportTable =
		(PIMAGE_IMPORT_DESCRIPTOR)(FOA + (DWORD)pDosHeader);
	PIMAGE_IMPORT_DESCRIPTOR tmpPImportTable = pImportTable;
	////size_t numOfImportTable = pOptionalHeader->DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	//printf("导入表");
	////for (size_t i = 0; i < numOfImportTable; i++);
	//while (pImportTable->Name != NULL)
	//{
	//	printf("导入的PE文件名称：");
	//	char * dwName = (char *)(RVA2FOA(pImportTable->Name) + (DWORD)pDosHeader);
	//	printf("%s\n", dwName);
	//	printf("导入的函数\n");
	//	//DWORD FirstThunk_FOA = RVA2FOA(pImportTable->OriginalFirstThunk);//INT
	//	DWORD FirstThunk_FOA = RVA2FOA(pImportTable->FirstThunk);//IAT
	//	PIMAGE_THUNK_DATA thunk =
	//		(PIMAGE_THUNK_DATA)(FirstThunk_FOA + (DWORD)pDosHeader);
	//	printf("Hint  Name \n");
	//	while (thunk->u1.Ordinal)
	//	{
	//		if (!IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
	//		{
	//			PIMAGE_IMPORT_BY_NAME functionInfo =
	//				(PIMAGE_IMPORT_BY_NAME)(RVA2FOA(thunk->u1.AddressOfData) + (DWORD)pDosHeader);
	//			printf("%04x %s\n", functionInfo->Hint, functionInfo->Name);
	//		}
	//		else
	//		{
	//			printf("%04x %s\n", thunk->u1.Ordinal & 0xffff, "(NULL)");
	//		}
	//		thunk++;
	//	}
	//	pImportTable++;
	//}
	return pImportTable;
}

PIMAGE_RESOURCE_DIRECTORY MyPe::GetResourceTable(DWORD dwResourceTableRva)
{

	if (m_buf == nullptr)
	{
		return PIMAGE_RESOURCE_DIRECTORY();
	}
	DWORD FOA = RVA2FOA(dwResourceTableRva);
	pResourceTables = (PIMAGE_RESOURCE_DIRECTORY)(FOA + (DWORD)pDosHeader);

	/*size_t szNumOfResource =
		pResourceTables->NumberOfNamedEntries +
		pResourceTables->NumberOfIdEntries;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntryTable =
		(PIMAGE_RESOURCE_DIRECTORY_ENTRY)((BYTE*)pResourceTables +
			sizeof(IMAGE_RESOURCE_DIRECTORY));
	printf("\nReLocal\n");
	for (size_t i = 0; i < szNumOfResource; i++)
	{
		if (pResourceEntryTable[i].NameIsString == 0)
		{
			if (pResourceEntryTable[i].Id < 0x10)
			{
				printf(" %s ", resourceType[pResourceEntryTable[i].Id - 1]);
			}
			else printf(" %x ", pResourceEntryTable[i].Id);
		}
		else
		{
			PIMAGE_RESOURCE_DIR_STRING_U pResourceDirTable =
				(PIMAGE_RESOURCE_DIR_STRING_U)(pResourceEntryTable[i].NameOffset +
				(DWORD)pResourceTables);
			size_t lenth = pResourceDirTable->Length + 1;
			wchar_t* sourceName = new wchar_t[lenth];
			wmemset(sourceName, 0, lenth);
			wmemcpy(sourceName, pResourceDirTable->NameString, pResourceDirTable->Length);
			printf("名称:%s", CW2A(sourceName).m_szBuffer);
		}
		if (pResourceEntryTable[i].DataIsDirectory == 1)
		{
			GetResourceTable(pResourceEntryTable[i].OffsetToDirectory +
				(DWORD)pOptionalHeader->DataDirectory[2].VirtualAddress);
		}
		else
		{
			PIMAGE_RESOURCE_DATA_ENTRY pResourceDataTable =
				(PIMAGE_RESOURCE_DATA_ENTRY)(pResourceEntryTable[i].OffsetToData +
				(DWORD)pResourceTables);
			printf("RVA:%x ", pResourceDataTable->OffsetToData);
			printf("大小:%x \n", pResourceDataTable->Size);
		}
	}*/
	return pResourceTables;
}

PIMAGE_BASE_RELOCATION MyPe::GetReLocalTAble()
{
	if (m_buf == nullptr)
	{
		return PIMAGE_BASE_RELOCATION();
	}
	typedef struct MyStruct
	{
		WORD offset : 12;
		WORD type : 4;
	}*pMyStruct;

	pReLocalTables =
		(PIMAGE_BASE_RELOCATION)(RVA2FOA(pOptionalHeader->DataDirectory[5].VirtualAddress) +
		(DWORD)pDosHeader);
	/*PIMAGE_BASE_RELOCATION pReLocalTable = pReLocalTables;

	while (pReLocalTable->VirtualAddress != NULL)
	{
		printf("VirtualAddress:%x\n", pReLocalTable->VirtualAddress);
		size_t szNumOfTable = (pReLocalTable->SizeOfBlock - 8) / 2;
		pMyStruct ReLocal = (pMyStruct)(pReLocalTable + 1);
		for (size_t i = 0; i < szNumOfTable; i++, ReLocal++)
		{
			if (ReLocal->type == 0x3)
			{
				printf("offset:0x%x \n", ReLocal->offset);
				printf("RVA:0x%x \n", ReLocal->offset + pReLocalTable->VirtualAddress);
				printf("FOA:0x%x \n", RVA2FOA(ReLocal->offset + pReLocalTable->VirtualAddress));
			}
		}
		pReLocalTable = (PIMAGE_BASE_RELOCATION)((BYTE*)pReLocalTable + pReLocalTable->SizeOfBlock);
	}*/

	return pReLocalTables;
}

PIMAGE_TLS_DIRECTORY MyPe::GetTlsTable()
{
	if (m_buf == nullptr)
	{
		return PIMAGE_TLS_DIRECTORY();
	}
	pTLSTables =
		(PIMAGE_TLS_DIRECTORY)(RVA2FOA(pOptionalHeader->DataDirectory[9].VirtualAddress) +
		(DWORD)pDosHeader);
	/*pTLSTables->StartAddressOfRawData;
	printf("StartAddressOfRawData:%x\n", pTLSTables->StartAddressOfRawData);
	DWORD StartAddressOfRawData =
		RVA2FOA(pTLSTables->StartAddressOfRawData - pOptionalHeader->ImageBase) + (DWORD)pDosHeader;
	printf("EndAddressOfRawData:%x\n", pTLSTables->EndAddressOfRawData);
	DWORD EndAddressOfRawData =
		RVA2FOA(pTLSTables->EndAddressOfRawData - pOptionalHeader->ImageBase) + (DWORD)pDosHeader;

	DWORD* pAddressOfCallBacks =
		(DWORD*)(RVA2FOA(pTLSTables->AddressOfCallBacks - pOptionalHeader->ImageBase) + (DWORD)pDosHeader);


	while (*pAddressOfCallBacks != NULL)
	{
		printf("C:%x\n", *(pAddressOfCallBacks++));
	}*/

	return PIMAGE_TLS_DIRECTORY();
}

PIMAGE_DELAYLOAD_DESCRIPTOR MyPe::GetDelayLoadTable()
{
	if (m_buf == nullptr)
	{
		return PIMAGE_DELAYLOAD_DESCRIPTOR();
	}
	pDelayLoad =
		(PIMAGE_DELAYLOAD_DESCRIPTOR)(RVA2FOA(pOptionalHeader->DataDirectory[13].VirtualAddress) +
		(DWORD)pDosHeader);
	return PIMAGE_DELAYLOAD_DESCRIPTOR();
}

CHAR * MyPe::FileBufferToImageBuffer()
{
	//开辟存储空间
	char* imageBuffer = new char[pOptionalHeader->SizeOfImage];
	memset(imageBuffer, 0, pOptionalHeader->SizeOfImage);
	//拷贝头
	memcpy(imageBuffer, m_buf, pOptionalHeader->SizeOfHeaders);
	//拷贝节
	auto pTmpSecHeader = pSectionHeader;
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		char* pSectionRaw = nullptr;
		pSectionRaw = (char*)(pTmpSecHeader->PointerToRawData + (DWORD)pDosHeader);
		char* pMemSection = nullptr;
		pMemSection = (char*)(pTmpSecHeader->VirtualAddress + (DWORD)imageBuffer);
		memcpy(pMemSection, pSectionRaw, pTmpSecHeader->SizeOfRawData);
		pTmpSecHeader++;
	}
	return imageBuffer;
}

BOOL MyPe::ChangeImportTable()
{
	//1.查看哪个字段有充足的空间存储所有导入表结构体数组

	//2.移动导入表至该地址
	//3.增加导入表结构
	return 0;
}

DWORD MyPe::filebuffertoimagebuffer()
{
	LPVOID pTempImageBuffer = nullptr;
	if (m_buf == nullptr)
	{
		printf("缓冲区指针无效");
		return 0;
	}
	//判断是否为有效的MZ 标记
	if (*(PDWORD)m_buf != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)m_buf;
	//判断是否为有效的PE标志
	if (*((PDWORD)((DWORD)m_buf + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的pe标志");
	}
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)m_buf + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNtHeader) + 4);
	//可选PE 头
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	//第一个节目录指针
	//pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

}

DWORD MyPe::RVA2FOA(DWORD RVA)
{
	//1.判断在那个区段
	IMAGE_SECTION_HEADER pTmpSectionHeader = { 0 };
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (pSectionHeader[i].VirtualAddress <= RVA &&
			RVA < pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData)
		{
			pTmpSectionHeader = pSectionHeader[i];
			break;
		}
	}
	//2.RVA >> FOA
	DWORD FOA = RVA - pTmpSectionHeader.VirtualAddress + pTmpSectionHeader.PointerToRawData;
	return FOA;
}

//WCHAR * DwToWchar(DWORD dwNum, int radix)
//{
//	char cBuffer[0x10] = { 0 };
//	_itoa_s(dwNum, cBuffer, radix);
//	CA2W cwBuffer(cBuffer);
//	WCHAR* wcBuffer = new WCHAR[0x10];
//	cwBuffer.m_szBuffer;
//	wmemcpy(wcBuffer, cwBuffer.m_szBuffer, 0x10);
//	return wcBuffer;
//}