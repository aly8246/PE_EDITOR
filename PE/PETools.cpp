#include "stdafx.h"
#include "PETEST.h"
#include "PETools.h"

char readFilePath[] = FILEPATH;
char SaveFilePath[] = NEWPATH;

LPVOID pFileBuf=NULL;
LPVOID pImgBuf =NULL;
DWORD sizeOfFile=NULL;


PIMAGE_DOS_HEADER pDosHeader = NULL;
PIMAGE_FILE_HEADER pPEHeader = NULL;
PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
PIMAGE_SECTION_HEADER pSectionHeader = NULL;
PIMAGE_NT_HEADERS32 pNTHeader = NULL;

PIMAGE_DATA_DIRECTORY pDirCtory = NULL;

PIMAGE_EXPORT_DIRECTORY pExport = NULL;
PIMAGE_BASE_RELOCATION pReLoaction = NULL;
PIMAGE_IMPORT_DESCRIPTOR pImport = NULL;
PIMAGE_RESOURCE_DIRECTORY pResource = NULL;


//读取文件到fileBuf里，返回buffer
LPVOID tpReadFileToBuf()
{
	FILE* fp = fopen(readFilePath, "rb+");
	if (!fp)
	{
		printf("文件打开失败！");
		system("pause");
		fclose(fp);
	}

	fseek(fp, 0, SEEK_END);
	sizeOfFile = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	pFileBuf = malloc(sizeOfFile);
	memset(pFileBuf, 0, sizeOfFile);
	if (!pFileBuf)
	{
		printf("分配缓冲区失败");
		system("pause");
		fclose(fp);
		free(pFileBuf);
	}

	size_t n = fread(pFileBuf, sizeOfFile, 1, fp);
	if (!n)
	{
		printf("分配缓冲区失败");
		system("pause");
		fclose(fp);
		free(pFileBuf);
	}

	fclose(fp);


	return pFileBuf;
}
//保存filebuf里修改好的数据到新的exe
LPVOID tpSaveBufToFile(LPVOID sFileBuf)
{
	if (!sFileBuf)
	{
		printf("没有正确读写fileBuf!"); system("pause"); return NULL;
	}

	FILE* fp = fopen(SaveFilePath, "wb");
	fwrite(sFileBuf, sizeof(sFileBuf), sizeOfFile / 4, fp);

	fclose(fp);
	free(pFileBuf);

	printf("存盘成功！\n");
	Sleep(1500);
	return 0;
}


//拉伸filebuf到ImageBuf
LPVOID tpFileBufToImgBuf(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("读取文件失败"); 
		system("pause");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	if (pOptionHeader->FileAlignment==pOptionHeader->SectionAlignment)
	{
		return pFileBuf;
	}

	pImgBuf = malloc(pOptionHeader->SizeOfImage);
	memset(pImgBuf, 0, pOptionHeader->SizeOfImage);

	memcpy(pImgBuf, pFileBuf, pOptionHeader->SizeOfHeaders);
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++,pSectionHeader++)
	{
		memcpy(    (LPBYTE)pImgBuf + pSectionHeader->VirtualAddress,
				   (LPBYTE)pFileBuf + pSectionHeader->PointerToRawData,
			       max(pSectionHeader->Misc.VirtualSize, pSectionHeader->SizeOfRawData)
			);
	}

	free(pFileBuf);
	pFileBuf = NULL;

	return pImgBuf;
}
//压缩ImageBuf到filebu
LPVOID tpImgbufToFileBuf(LPVOID pImgBuf)
{
	if (!pImgBuf)
	{
		printf("读取文件失败");
		system("pause");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pImgBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	if (pOptionHeader->FileAlignment == pOptionHeader->SectionAlignment)
	{
		return pFileBuf;
	}


	pFileBuf = malloc(sizeOfFile);
	memset(pFileBuf, 0, sizeOfFile);

	memcpy(pFileBuf, pImgBuf, pOptionHeader->SizeOfHeaders);
	for (DWORD i = 0; i < pPEHeader->NumberOfSections;i++,pSectionHeader++)
	{
		memcpy(    (LPBYTE)pFileBuf + pSectionHeader->PointerToRawData,
				   (LPBYTE)pImgBuf + pSectionHeader->VirtualAddress,
				   max(pSectionHeader->Misc.VirtualSize, pSectionHeader->SizeOfRawData)
			  );
	}


	free(pImgBuf);
	pImgBuf = NULL;
	return pFileBuf;
}


DWORD RVAtoFOA(DWORD m_Rva, LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("读取文件失败");
		return NULL;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	DWORD fSeciton = NULL;
	DWORD m_Foa = NULL;

	for (DWORD i = 0; i < (DWORD)pPEHeader->NumberOfSections; i++, pSectionHeader++)
	{
		fSeciton = m_Rva - (DWORD)pSectionHeader->VirtualAddress;
		if (fSeciton < max(pSectionHeader->Misc.VirtualSize, pSectionHeader->SizeOfRawData)){

			break;
		}
		if (m_Rva<pOptionHeader->SizeOfHeaders || m_Rva>pOptionHeader->SizeOfImage ||
			m_Rva == pSectionHeader->PointerToRawData ||
			pOptionHeader->FileAlignment == pOptionHeader->SectionAlignment
			){//如果 rva小于pe头或者大于imagebase说明不需要RVAtoFOA,如果 filebuf的内存对齐和文件对齐一样也不需要
			return m_Rva;
			break;
		}
		fSeciton = m_Rva;
	}

	//文件偏移=Rva相对地址偏移减去该节的rva+该地址所在节的物理偏移
	m_Foa = m_Rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;

	return m_Foa;
}
DWORD FOAtoRva(DWORD m_Foa, LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("读取文件失败");
		return NULL;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	DWORD fSeciton = NULL;
	DWORD m_Rva = NULL;

	for (DWORD i = 0; i < (DWORD)pPEHeader->NumberOfSections; i++, pSectionHeader++)
	{
		fSeciton = m_Foa - (DWORD)pSectionHeader->PointerToRawData;
		if (fSeciton < max(pSectionHeader->Misc.VirtualSize, pSectionHeader->SizeOfRawData)&&pSectionHeader->SizeOfRawData!=0){

			break;
		}
		if (m_Foa<pOptionHeader->SizeOfHeaders || m_Foa>pOptionHeader->SizeOfImage ||
			m_Foa == pSectionHeader->PointerToRawData ||
			pOptionHeader->FileAlignment == pOptionHeader->SectionAlignment
			){//如果 rva小于pe头或者大于imagebase说明不需要RVAtoFOA,如果 filebuf的内存对齐和文件对齐一样也不需要
			return m_Foa;
			break;
		}
		fSeciton = m_Foa;
	}

	//文件偏移=Rva相对地址偏移减去该节的rva+该地址所在节的物理偏移
	m_Rva = m_Foa - pSectionHeader->PointerToRawData + pSectionHeader->VirtualAddress;
	return m_Rva;
}


//清除PE头里的垃圾，有更多的空间添加一个新节
LPVOID tpCleanPeHeader(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("读取文件失败");
		system("pause");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	
	DWORD sizeOfHeader = pOptionHeader->SizeOfHeaders;
	LPVOID pTempBuf = NULL;
	pTempBuf = malloc(pOptionHeader->SizeOfHeaders);
	memset(pTempBuf, 0, pOptionHeader->SizeOfHeaders);

	memcpy((LPBYTE)pTempBuf, pDosHeader, IMAGE_SIZE_DOS_HEADER);
	memcpy((LPBYTE)pTempBuf + IMAGE_SIZE_DOS_HEADER, pNTHeader, 0x4 + IMAGE_SIZEOF_FILE_HEADER + pPEHeader->SizeOfOptionalHeader);
	pDosHeader = (PIMAGE_DOS_HEADER)pTempBuf;
	pDosHeader->e_lfanew = 0x40;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	//节表起始位置=dos头大小+标记大小0x4+file头大小+optinal头大小
	DWORD n = 0;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections;i++,pSectionHeader++)
	{
		memcpy((LPBYTE)pTempBuf + IMAGE_SIZE_DOS_HEADER + 0x4 + IMAGE_SIZEOF_FILE_HEADER + pPEHeader->SizeOfOptionalHeader + n,
			pSectionHeader,IMAGE_SIZEOF_SECTION_HEADER
			);
		n += IMAGE_SIZEOF_SECTION_HEADER;
	}

	memset(pFileBuf, 0, sizeOfHeader);
	memcpy(pFileBuf, pTempBuf, sizeOfHeader);

	free(pTempBuf);
	pTempBuf = NULL;
	return pFileBuf;
}
//清除pe头垃圾并且添加一个新节
LPVOID tpNewSection(LPVOID pFileBuf)
{
	pFileBuf = tpCleanPeHeader(pFileBuf);

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER pNewSection = pSectionHeader + pPEHeader->NumberOfSections;
	PIMAGE_SECTION_HEADER pEndSection = pSectionHeader + pPEHeader->NumberOfSections - 1;

	for (int i = 0; i < SectionNameLen; i++){
		if (SectionName[1] != 0)
			pNewSection->Name[i] = SectionName[i];
	}
	pNewSection->Misc.VirtualSize = SectnionLen;
	pNewSection->VirtualAddress = pEndSection->VirtualAddress + max(pEndSection->Misc.VirtualSize, pEndSection->SizeOfRawData);
	pNewSection->SizeOfRawData = SectnionLen;
	pNewSection->PointerToRawData = pEndSection->PointerToRawData + max(pEndSection->Misc.VirtualSize, pEndSection->SizeOfRawData);
	pNewSection->Characteristics = pSectionHeader->Characteristics;

	pPEHeader->NumberOfSections += 1;
	pOptionHeader->SizeOfImage += SectnionLen;
	sizeOfFile += SectnionLen;


	LPVOID pNewFileBuf = NULL;
	pNewFileBuf = malloc(sizeOfFile);
	memcpy(pNewFileBuf, pFileBuf, pOptionHeader->SizeOfHeaders);

	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++, pSectionHeader++)
	{
		memcpy((LPBYTE)pNewFileBuf + pSectionHeader->PointerToRawData,
			(LPBYTE)pFileBuf + pSectionHeader->PointerToRawData,
			pSectionHeader->SizeOfRawData);
	}
	pSectionHeader--;
	memset((LPBYTE)pNewFileBuf+pSectionHeader->PointerToRawData, 0, 0x1000);
	return pNewFileBuf;
}
//pe头清理垃圾也不够再添加一个新的节，只能扩大节
LPVOID tpExpSection(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("error");
		return false;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER pEndSection = pSectionHeader + pPEHeader->NumberOfSections - 1;
	pEndSection->Misc.VirtualSize += ExpandSection;
	pEndSection->SizeOfRawData += ExpandSection;
	pOptionHeader->SizeOfImage += ExpandSection;
	pEndSection->Characteristics = pSectionHeader->Characteristics;
	sizeOfFile += ExpandSection;

	LPVOID pNewFileBuf = NULL;
	pNewFileBuf = malloc(sizeOfFile);
	memcpy(pNewFileBuf, pFileBuf, pOptionHeader->SizeOfHeaders);

	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++, pSectionHeader++)
	{
		memcpy((LPBYTE)pNewFileBuf + pSectionHeader->PointerToRawData,
			(LPBYTE)pFileBuf + pSectionHeader->PointerToRawData,
			pSectionHeader->SizeOfRawData);
	}
	pFileBuf = pNewFileBuf;
	return pFileBuf;
}

//任意节添加测试代码
LPVOID tpSectionAddCode(LPVOID pFileBuf,char SectionID)
{
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	pSectionHeader += SectionID;

	if (SectionID > pPEHeader->NumberOfSections)
	{
		printf("所选择的节不存在，最多只有%d%个节", pPEHeader->NumberOfSections);
		return false;
	}
	else if (pSectionHeader->Misc.VirtualSize > pSectionHeader->SizeOfRawData)
	{
		printf("此节的空白区域不够添加代码");
		return false;
	}

	LPBYTE CodeBegin = (LPBYTE)pFileBuf + RVAtoFOA(pSectionHeader->VirtualAddress, pFileBuf);
	memcpy(CodeBegin, shellcode, SHELLCODELENGTH);

	//e8 CALL的偏移地址=MessageBox地址  - (ImageBase           +   自己的oep  +  e8下一行指令的地址 -  文件缓存)
	DWORD callAddr = MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((DWORD)CodeBegin + 0xD - (DWORD)pFileBuf));
	//e9 JMP的偏移地址=原来的oep  -  (自己的oep   +   e9下一行地址 -  文件缓存)
	DWORD jmpAddr = pOptionHeader->AddressOfEntryPoint - ((DWORD)CodeBegin + 0x12 - (DWORD)pFileBuf);

	*(DWORD*)(CodeBegin + 0x9) = callAddr;
	*(DWORD*)(CodeBegin + 0xE) = jmpAddr;

	pOptionHeader->AddressOfEntryPoint = (DWORD)CodeBegin - (DWORD)pFileBuf;

	DWORD x = pSectionHeader->Characteristics;
	DWORD y = (pSectionHeader-pPEHeader->NumberOfSections+1)->Characteristics;
	pSectionHeader->Characteristics = x | y;

	return pFileBuf;
}

//移动导出表新加节
LPVOID tpMoveExportTable(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("读取文件失败");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//添加新节完成初始化工作，拿到foa
	PIMAGE_SECTION_HEADER pEndSection = pSectionHeader + pPEHeader->NumberOfSections - 1;
	LPBYTE nExportBegin = (LPBYTE)pFileBuf + (DWORD)pEndSection->PointerToRawData;

	//导出表
	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	pDataDir = (PIMAGE_DATA_DIRECTORY)((PBYTE)pFileBuf + (DWORD)pDosHeader->e_lfanew + IMAGE_DATADIR_OFFSET);
	if (pDataDir->VirtualAddress == 0 && pDataDir->Size == 0) return false;

	pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pFileBuf + RVAtoFOA((pDataDir + IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress, pFileBuf));
	
	/************************************************************************//* 
	初始化需要移动的小表指针
	拿到原来的小表的地址指针
	把原来的表复制到新地址里
	修复导出表的地址成正确的
	计算下一个可以存放的地址
	*//************************************************************************/



	//准备开始移动导出表，先移动到处地址表,修复导出表的AddressOfFunctions,计算下一个节空闲位置
	LPDWORD funAddrIndex = NULL;
	funAddrIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfFunctions, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportBegin, funAddrIndex, 4 * pExport->NumberOfFunctions);
	pExport->AddressOfFunctions = FOAtoRva((DWORD)nExportBegin - (DWORD)pFileBuf, pFileBuf);
	LPBYTE nExportNext = (LPBYTE)pFileBuf + (DWORD)pEndSection->PointerToRawData + 4 * pExport->NumberOfFunctions;

	printf("新的函数地址表的RVA：0x%x------新的函数地址表的FOA:0x%x\n", pExport->AddressOfFunctions, (DWORD)nExportNext - (DWORD)pFileBuf);


	//移动序号表到地址表的后面，修复导出表的AddressOfNameOrdinals,计算下一个节空闲位置
	LPWORD funOrdinalsIndex = NULL;
	funOrdinalsIndex = (LPWORD)(RVAtoFOA(pExport->AddressOfNameOrdinals, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportNext, funOrdinalsIndex, 2 * pExport->NumberOfNames);
	pExport->AddressOfNameOrdinals = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	nExportNext += 2 * pExport->NumberOfNames;

	printf("新的函数序号表的RVA：0x%x------新的函数序号表的FOA:0x%x\n", pExport->AddressOfNameOrdinals, (DWORD)nExportNext - (DWORD)pFileBuf);

	//移动名字表里的地址里的值，动态计算下一个地址，并且直接修复名字表里的地址，然后直接移动名字表
	LPDWORD funNameIndex = NULL;
	LPDWORD funNameNext =(LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf);
	LPBYTE funName = NULL;

	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		funNameIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf)+i;
		funName = RVAtoFOA(*funNameIndex, pFileBuf) + (LPBYTE)pFileBuf;

		memcpy(nExportNext, funName, strlen(funName)+1);//拷贝第i个函数名到新地址

	
		funNameNext[i] = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);

		nExportNext += strlen(funName)+1;
	}

	funNameIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportNext, funNameIndex, 4 * pExport->NumberOfNames);
	pExport->AddressOfNames = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	nExportNext += 4 * pExport->NumberOfNames;

	printf("新的函数名称表的RVA：0x%x------新的函数名称表的FOA:0x%x\n", pExport->AddressOfNames, (DWORD)nExportNext - (DWORD)pFileBuf);

	//最后移动整个导出表结构，并且目录结构表指向新的导出表结构
	memcpy(nExportNext, pExport, IMAGE_SIZE_EXPORTTABLE);
	pDataDir->VirtualAddress = FOAtoRva((DWORD)nExportNext-(DWORD)pFileBuf, pFileBuf);
	printf("新的导出表的RVA：0x%x-----新的导出表的FOA：0x%x\n", pDataDir->VirtualAddress, (DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);

	return pFileBuf;
}

//移动重定位表到新节
LPVOID tpMoveRelocationTable(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("读取文件失败");
		return false;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER pEndSection = pSectionHeader + pPEHeader->NumberOfSections - 1;
	LPBYTE nRelocationNext = (LPBYTE)pFileBuf + (DWORD)pEndSection->PointerToRawData;//下一个新节中的重定位表


	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	pDataDir = (PIMAGE_DATA_DIRECTORY)((PBYTE)pFileBuf + (DWORD)pDosHeader->e_lfanew + IMAGE_DATADIR_OFFSET);

	pReLoaction = (PIMAGE_BASE_RELOCATION)(RVAtoFOA((pDataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress, pFileBuf) + (LPBYTE)pFileBuf);
	if (pReLoaction->VirtualAddress == 0 && pReLoaction->SizeOfBlock == 0) return false;

	PIMAGE_BASE_RELOCATION nextRelocatin = NULL;//下一个重定位表

	(pDataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress = FOAtoRva((DWORD)nRelocationNext - (DWORD)pFileBuf, pFileBuf);

	for (DWORD i = 0;;i++)
	{
		if (nextRelocatin != 0) pReLoaction = nextRelocatin;

		memcpy(nRelocationNext, pReLoaction, pReLoaction->SizeOfBlock);

		nRelocationNext += pReLoaction->SizeOfBlock;

		nextRelocatin = (PIMAGE_BASE_RELOCATION)(((DWORD)pReLoaction) + pReLoaction->SizeOfBlock);
		if (nextRelocatin->SizeOfBlock > pReLoaction->VirtualAddress || nextRelocatin->VirtualAddress == nextRelocatin->SizeOfBlock){
		break;
		}
	}
	return pFileBuf;
}

//移动导出表和重定位表
LPVOID tpmoveRelocation_Export_table(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("读取文件失败");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//添加新节完成初始化工作，拿到foa
	PIMAGE_SECTION_HEADER pEndSection = pSectionHeader + pPEHeader->NumberOfSections - 1;
	LPBYTE nExportBegin = (LPBYTE)pFileBuf + (DWORD)pEndSection->PointerToRawData;

	//导出表
	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	pDataDir = (PIMAGE_DATA_DIRECTORY)((PBYTE)pFileBuf + (DWORD)pDosHeader->e_lfanew + IMAGE_DATADIR_OFFSET);
	if (pDataDir->VirtualAddress == 0 && pDataDir->Size == 0) return false;

	pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pFileBuf + RVAtoFOA((pDataDir + IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress, pFileBuf));

	/************************************************************************//*
	初始化需要移动的小表指针
	拿到原来的小表的地址指针
	把原来的表复制到新地址里
	修复导出表的地址成正确的
	计算下一个可以存放的地址
	*//************************************************************************/



	//准备开始移动导出表，先移动到处地址表,修复导出表的AddressOfFunctions,计算下一个节空闲位置
	LPDWORD funAddrIndex = NULL;
	funAddrIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfFunctions, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportBegin, funAddrIndex, 4 * pExport->NumberOfFunctions);
	pExport->AddressOfFunctions = FOAtoRva((DWORD)nExportBegin - (DWORD)pFileBuf, pFileBuf);
	LPBYTE nExportNext = (LPBYTE)pFileBuf + (DWORD)pEndSection->PointerToRawData + 4 * pExport->NumberOfFunctions;

	printf("新的函数地址表的RVA：0x%x------新的函数地址表的FOA:0x%x\n", pExport->AddressOfFunctions, (DWORD)nExportNext - (DWORD)pFileBuf);


	//移动序号表到地址表的后面，修复导出表的AddressOfNameOrdinals,计算下一个节空闲位置
	LPWORD funOrdinalsIndex = NULL;
	funOrdinalsIndex = (LPWORD)(RVAtoFOA(pExport->AddressOfNameOrdinals, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportNext, funOrdinalsIndex, 2 * pExport->NumberOfNames);
	pExport->AddressOfNameOrdinals = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	nExportNext += 2 * pExport->NumberOfNames;

	printf("新的函数序号表的RVA：0x%x------新的函数序号表的FOA:0x%x\n", pExport->AddressOfNameOrdinals, (DWORD)nExportNext - (DWORD)pFileBuf);

	//移动名字表里的地址里的值，动态计算下一个地址，并且直接修复名字表里的地址，然后直接移动名字表
	LPDWORD funNameIndex = NULL;
	LPDWORD funNameNext = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf);
	LPBYTE funName = NULL;

	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		funNameIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf) + i;
		funName = RVAtoFOA(*funNameIndex, pFileBuf) + (LPBYTE)pFileBuf;

		memcpy(nExportNext, funName, strlen(funName) + 1);//拷贝第i个函数名到新地址


		funNameNext[i] = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);

		nExportNext += strlen(funName) + 1;
	}

	funNameIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportNext, funNameIndex, 4 * pExport->NumberOfNames);
	pExport->AddressOfNames = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	nExportNext += 4 * pExport->NumberOfNames;

	printf("新的函数名称表的RVA：0x%x------新的函数名称表的FOA:0x%x\n", pExport->AddressOfNames, (DWORD)nExportNext - (DWORD)pFileBuf);

	//最后移动整个导出表结构，并且目录结构表指向新的导出表结构
	memcpy(nExportNext, pExport, IMAGE_SIZE_EXPORTTABLE);
	pDataDir->VirtualAddress = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	printf("新的导出表的RVA：0x%x-----新的导出表的FOA：0x%x\n", pDataDir->VirtualAddress, (DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	//导出表结束位置=
	nExportNext += IMAGE_SIZE_EXPORTTABLE;



	/************************************************************************/
	/*					新重定位表起始位置是导出表结束位置                  */
	/************************************************************************/
	//移动重定位表，新表开始的位置为导出表结束的位置
	LPBYTE nRelocationNext = nExportNext;//下一个新节中的重定位表
	PIMAGE_BASE_RELOCATION nextRelocatin = NULL;//下一个重定位表

	pReLoaction = (PIMAGE_BASE_RELOCATION)(RVAtoFOA((pDataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress, pFileBuf) + (LPBYTE)pFileBuf);

	(pDataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);

	for (DWORD i = 0;; i++)
	{
		if (nextRelocatin != 0) pReLoaction = nextRelocatin;

		memcpy(nRelocationNext, pReLoaction, pReLoaction->SizeOfBlock);

		nRelocationNext += pReLoaction->SizeOfBlock;

		nextRelocatin = (PIMAGE_BASE_RELOCATION)(((DWORD)pReLoaction) + pReLoaction->SizeOfBlock);
		if (nextRelocatin->SizeOfBlock > pReLoaction->VirtualAddress || nextRelocatin->VirtualAddress == nextRelocatin->SizeOfBlock){
			break;
		}
	}
	return pFileBuf;

}

//修复重定位表
LPVOID tpRepairRelocationTable(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("读取文件失败");
		return false;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	pDataDir = (PIMAGE_DATA_DIRECTORY)((PBYTE)pFileBuf + (DWORD)pDosHeader->e_lfanew + IMAGE_DATADIR_OFFSET);

	pReLoaction = (PIMAGE_BASE_RELOCATION)(RVAtoFOA((pDataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress, pFileBuf) + (LPBYTE)pFileBuf);
	if (pReLoaction->VirtualAddress == 0 && pReLoaction->SizeOfBlock == 0) return false;

	//假设原来的imagebase是10000000，在内存中变成了20000000
	DWORD oldImageBase = 0x10000000;
	pOptionHeader->ImageBase = 0x20000000;
	DWORD newImageBase = pOptionHeader->ImageBase;



	PIMAGE_BASE_RELOCATION nextRelocatin = NULL;
	for (DWORD i = 0;; i++)
	{
		if (nextRelocatin != 0) pReLoaction = nextRelocatin;

		printf("============================================\n");
		printf("第%d个重定位表:%x\n", i + 1, pReLoaction->VirtualAddress);

		LPWORD pReLoactionItem = (LPWORD)pReLoaction + 4;
		DWORD pReLoactionCount = (pReLoaction->SizeOfBlock - 8) >> 1;//需要修复的个数为整个块大小减去头再除以2

		for (DWORD i = 0; i < pReLoactionCount; i++)//输出高位为3的低12，再加上重定位表的rva等于真正要修复的地址W
		{
			if (pReLoactionItem[i] >> 12)
				//重定位表：01 30 -- 3001 -- 0011 0000 0000 0000    ，通过移位判断这个值=3，是有效值，继续输出，计算后的偏移=表的rva+（3001的低12位）
				printf("Index:%d,    重定位表中：%x    计算后的偏移：%x\n", i, pReLoactionItem[i], pReLoaction->VirtualAddress + (pReLoactionItem[i] & 0x0FFF));

				LPDWORD pImage_RepairRelocation = NULL;//需要修复的第一个地址是418+filebuffer
				pImage_RepairRelocation =(LPDWORD)(RVAtoFOA(pReLoaction->VirtualAddress + (pReLoactionItem[i] & 0x0FFF), pFileBuf)+(LPBYTE)pFileBuf);
				*pImage_RepairRelocation += newImageBase - oldImageBase;//拿到重定位表里的值，判断高12位是否需要修复，再拿到低12位，加上这个段的rva，等于需要修复的rva，
																		//转换成foa。取地址里面的值全部加上差值,重定位表修复完成
		}
		//下一个表等于当前表+上当前的大小
		nextRelocatin = (PIMAGE_BASE_RELOCATION)(((DWORD)pReLoaction) + pReLoaction->SizeOfBlock);
		if (nextRelocatin->SizeOfBlock > pReLoaction->VirtualAddress || nextRelocatin->VirtualAddress == nextRelocatin->SizeOfBlock){
			break;
		}
	}


	return pFileBuf;
}