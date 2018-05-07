#include "stdafx.h"
#include "PETEST.h"
#include "PETools.h"



BYTE shellcode[] =
{
	0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00,
	0xE8, 0x00, 0x00, 0x00, 0x00,
	0xE9, 0x00, 0x00, 0x00
};
BYTE SectionName[] = {
	0x2E, 0x63, 0x6F, 0x64, 0x65, 0x00, 0x00, 0x00
};

//打印pe头
LPVOID printfHeaderAndSection()
{
	pFileBuf = tpReadFileToBuf();
	if (!pFileBuf)
	{
		printf("读取文件失败");
		free(pFileBuf);
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	if (*((PWORD)pFileBuf) != IMAGE_DOS_SIGNATURE){
		printf("不是有效的win32应用程序"); return NULL;
	}
	printf("************DOS头************************************************\n");
	printf("MZ偏移: %x\n", pDosHeader->e_magic);
	printf("e_cblp      文件最后页的字数:%x\n", pDosHeader->e_cblp);
	printf("e_cp        文件页数:%x\n", pDosHeader->e_cp);
	printf("e_crlc      重定义元素个数:%x\n", pDosHeader->e_crlc);
	printf("e_cparhdr   头部尺寸，以段落为单位:%x\n", pDosHeader->e_cparhdr);
	printf("e_minalloc  所需最小附加段:%x\n", pDosHeader->e_minalloc);
	printf("e_maxalloc  所需最大附加段:%x\n", pDosHeader->e_maxalloc);
	printf("e_ss        DOS代码入口SS:%x\n", pDosHeader->e_ss);
	printf("e_sp        DOS代码入口SP:%x\n", pDosHeader->e_sp);
	printf("e_csum      校验和:%x\n", pDosHeader->e_csum);
	printf("e_cs        DOS代码入口CS:%x\n", pDosHeader->e_cs);
	printf("e_ip        DOS代码入口IP:%x\n", pDosHeader->e_ip);
	printf("e_lfarlc    重分配表文件地址:%x\n", pDosHeader->e_lfarlc);
	printf("e_ovno      覆盖号:%x\n", pDosHeader->e_ovno);
	printf("e_res[4]    保留字:%x\n", pDosHeader->e_res[0]);
	printf("e_oemid     OEM标识符[相对e_oeminfo]:%x\n", pDosHeader->e_oemid);
	printf("e_oeminfo   OEM信息:%x\n", pDosHeader->e_oeminfo);
	printf("e_res2[10]  保留字2:%x\n", pDosHeader->e_res2[0]);
	printf("e_lfanew    PE偏移:%x\n", pDosHeader->e_lfanew);
	printf("************NT头************\n");
	printf("NTsignature:						 %x-%x\n", (DWORD)&(pNTHeader->Signature), pNTHeader->Signature);
	printf("NT-FileHeader:						 %x\n", pNTHeader->FileHeader);
	printf("************NT头_标准pe头****************************************************\n");
	printf("Machine			    机器运行平台:%x\n", pPEHeader->Machine);
	printf("NumberOfSecions		节表的数目:%x\n", pPEHeader->NumberOfSections);
	printf("TimeDateStamp		文件创建的时间戳:%x\n", pPEHeader->TimeDateStamp);
	printf("PointOfSymbolTable  指向符号表（用于调试）:%x\n", pPEHeader->PointerToSymbolTable);
	printf("NumberOfSymbols     符号表中的个数（用于调试）:%x\n", pPEHeader->NumberOfSymbols);
	printf("SizeOfOptionHeaders 可选pe头的长度:%x\n", pPEHeader->SizeOfOptionalHeader);
	printf("Charteristics	    特征值/文件信息标志:			%x\n", pPEHeader->Characteristics);
	//可选pe头=
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("************NT头_可选pe头****************************************************\n");
	printf("Magic				        标志字（幻数）,常值为\"10Bh\"%x\n", pOptionHeader->Magic);
	printf("MajorLinkerVersion			链接器主版本号%x\n", pOptionHeader->MajorLinkerVersion);
	printf("MinorLinkerVersion			链接器次版本号%x\n", pOptionHeader->MinorLinkerVersion);
	printf("SizeOfCode					代码段大小%x\n", pOptionHeader->SizeOfCode);
	printf("SizeOfInitializedDate		已初始化数据块大小%x\n", pOptionHeader->SizeOfInitializedData);
	printf("sizeOfUninitializedDate		未初始化数据块大小%x\n", pOptionHeader->SizeOfUninitializedData);
	printf("AddressEntryPoint(RVA)		程序执行的入口，RVA%x\n", pOptionHeader->AddressOfEntryPoint);
	printf("BaseOfCode					代码块起始地址%x\n", pOptionHeader->BaseOfCode);
	printf("BaseOfDate					数据块起始地址%x\n", pOptionHeader->BaseOfData);
	printf("ImageBase					镜像基址%x\n", pOptionHeader->ImageBase);
	printf("SectionAlignment			内存对齐%x\n", pOptionHeader->SectionAlignment);
	printf("FileAlignment				文件对齐%x\n", pOptionHeader->FileAlignment);
	printf("MajorOperatingSystemVersion 操作系统主版本号%x\n", pOptionHeader->MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion 操作系统次版本号%x\n", pOptionHeader->MinorOperatingSystemVersion);
	printf("MajorImageVersion			可执行文件的主版本号，自定义%x\n", pOptionHeader->MajorImageVersion);
	printf("MinorImageVersion			可执行文件的次版本号，自定义%x\n", pOptionHeader->MinorImageVersion);
	printf("MajorSubsystemVersion		子系统主版本号%x\n", pOptionHeader->MajorSubsystemVersion);
	printf("MinorSubsystemVersion		子系统次版本号%x\n", pOptionHeader->MinorSubsystemVersion);
	printf("Win32VersionValue			保留，总是\"00000000\"%x\n", pOptionHeader->Win32VersionValue);
	printf("SizeOfImage					整个pe文件装在后的镜像大小%x\n", pOptionHeader->SizeOfImage);
	printf("SizeOfHeader				PE头和节表的大小%x\n", pOptionHeader->SizeOfHeaders);
	printf("CheckSum					CRC校验和%x\n", pOptionHeader->CheckSum);
	printf("Subsystem					子系统:控制台/字符%x\n", pOptionHeader->Subsystem);
	printf("DllCharacteristics			DllMain()何时被调用%x\n", pOptionHeader->DllCharacteristics);
	printf("SizeOfStackReserve			初始化时为线程保留的栈大小%x\n", pOptionHeader->SizeOfStackReserve);
	printf("SizeOfStackCommint			初始化时线程实际使用栈大小%x\n", pOptionHeader->SizeOfStackCommit);
	printf("SizeOfHeapReserve			初始化时为进程保留的堆大小%x\n", pOptionHeader->SizeOfHeapReserve);
	printf("SizeOfHeapCommint			初始化时进程实际使用堆大小%x\n", pOptionHeader->SizeOfHeapCommit);
	printf("LoderFlages					设置自动调用断点或调试器%x\n", pOptionHeader->LoaderFlags);
	printf("NumberOfRvaAndSize			数据目录结构的数量总是10h%x\n", pOptionHeader->NumberOfRvaAndSizes);

	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		//计算第一个节表的位置
		pSectionHeader += i;
		printf("************第%d节表************\n", i + 1);
		printf(" Name: %x-%x%x%x%x%x%x%x%x\n",
			(DWORD)&(pSectionHeader->Name),
			pSectionHeader->Name[0],
			pSectionHeader->Name[1],
			pSectionHeader->Name[2],
			pSectionHeader->Name[3],
			pSectionHeader->Name[4],
			pSectionHeader->Name[5],
			pSectionHeader->Name[6],
			pSectionHeader->Name[7]);
		printf(" 节表名字: %x-------%s\n", (DWORD)&(pSectionHeader->Name), pSectionHeader->Name);
		printf(" VirtualAddress: %x-------%x\n", (DWORD)&(pSectionHeader->VirtualAddress), pSectionHeader->VirtualAddress);
		printf(" PointerToRawData: %x-------%x\n", (DWORD)&(pSectionHeader->PointerToRawData), pSectionHeader->PointerToRawData);
	}

	tpSaveBufToFile(pFileBuf);
	return 0;
}

//测试拉伸
VOID testStretching()
{
	pFileBuf=tpReadFileToBuf();
	if (!pFileBuf)
	{
		printf("读取文件失败");
		free(pFileBuf);
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	if (*((PWORD)pFileBuf) != IMAGE_DOS_SIGNATURE){
		printf("不是有效的win32应用程序");
	}
	pImgBuf=tpFileBufToImgBuf(pFileBuf);
	pFileBuf = tpImgbufToFileBuf(pImgBuf);

	tpSaveBufToFile(pFileBuf);
}

//测试rva和foa的互相转换
VOID TEST_RVA_FOA()
{
	pFileBuf = tpReadFileToBuf();
	DWORD Rva1 = (DWORD)0x9001;
	DWORD Foa1 = NULL;
	DWORD Rva2 = NULL;
	DWORD Foa2 = (DWORD)0x7801;

	Foa1 = RVAtoFOA(Rva1, pFileBuf);
	printf("虚拟地址对应的foa是%x\n", Foa1);

	Rva2 = FOAtoRva(Foa2, pFileBuf);
	printf("物理地址对应的rva是%x\n", Rva2);
}

//测试清理pe头垃圾
extern VOID testCleanPeHeader()
{
	pFileBuf = tpReadFileToBuf();
	if (!pFileBuf)
	{
		printf("读取文件失败");
		free(pFileBuf);
	}
	pFileBuf=tpCleanPeHeader(pFileBuf);
	tpSaveBufToFile(pFileBuf);
}

//测试清理pe头垃圾并且添加新节
VOID testNewSetion()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpNewSection(pFileBuf);
	tpSaveBufToFile(pFileBuf);
}
//测试扩大最后一个节
VOID	testExpSection()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpExpSection(pFileBuf);
	tpSaveBufToFile(pFileBuf);
}

//测试任意节 添加代码
VOID testSectionAddCode()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpExpSection(pFileBuf);
	pFileBuf = tpSectionAddCode(pFileBuf, 0);
	tpSaveBufToFile(pFileBuf);
}

//打印导出表
VOID PrintfExportTable()
{
	pFileBuf = tpReadFileToBuf();
	if (!pFileBuf)
	{
		printf("读取文件失败");
	}

	pFileBuf = tpCleanPeHeader(pFileBuf);

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	if (*((PWORD)pFileBuf) != IMAGE_DOS_SIGNATURE){
		printf("不是有效的win32应用程序");
	}

	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	pDataDir = (PIMAGE_DATA_DIRECTORY)((PBYTE)pFileBuf + (DWORD)pDosHeader->e_lfanew + IMAGE_DATADIR_OFFSET);
	
	pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pFileBuf + RVAtoFOA((pDataDir + IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress, pFileBuf));


	LPDWORD funNameIndex = NULL;
	LPBYTE funName = NULL;

	LPWORD funOrdinalsIndex = NULL;
	DWORD funOrdinals = NULL;

	LPDWORD funAddrIndex = NULL;
	DWORD funAddr = NULL;

	
	printf("====================================================================\n");
	printf("时间戳----------------------%d---------\n", pExport->TimeDateStamp);
	LPDWORD pName = (LPDWORD)((DWORD)RVAtoFOA(pExport->Name, pFileBuf) + (LPBYTE)pFileBuf);
	printf("指向该导出表名字字符串------%s---------\n", pName);
	printf("导出函数的起始序号----------%d---------\n", pExport->Base);
	printf("所有导出函数的个数----------%d---------\n", pExport->NumberOfFunctions);
	printf("名字导出函数的个数----------%d---------\n", pExport->NumberOfNames);
	printf("====================================================================\n");

	for (DWORD i = 0; i < pExport->NumberOfNames;i++)
	{
		funNameIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf) + i;
		funName = RVAtoFOA(*funNameIndex, pFileBuf) + (LPBYTE)pFileBuf;

		funOrdinalsIndex = (LPWORD)(RVAtoFOA(pExport->AddressOfNameOrdinals, pFileBuf) + (LPBYTE)pFileBuf) + i;
		funOrdinals = (DWORD)*funOrdinalsIndex;

		funAddrIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfFunctions, pFileBuf) + (LPBYTE)pFileBuf) + funOrdinals;
		funAddr=(DWORD)*funAddrIndex;

		
		printf("函数名字:%s---名字表中的FOA:%x---函数序号:%x---序号表中的FOA:%x---函数地址%x---地址表中的FOA:%x:\n", 
			funName, funNameIndex - (LPDWORD)pFileBuf,
				funOrdinals + pExport->Base, funOrdinalsIndex - (LPWORD)pFileBuf,
				funAddr,funAddrIndex-(LPDWORD)pFileBuf
				);
	}

	tpSaveBufToFile(pFileBuf);

	//pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pFileBuf+RVAtoFOA())	IMAGE_DIRECTORY_ENTRY_EXPORT

}

//测试移动导出表到新节
VOID testMoveExportTableToNewSection()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpNewSection(pFileBuf);

	pFileBuf = tpMoveExportTable(pFileBuf);

	tpSaveBufToFile(pFileBuf);
}

//打印重定位表
VOID PrintfRelocationTable()
{
	pFileBuf = tpReadFileToBuf();
	if (!pFileBuf)
	{
		printf("读取文件失败");
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	pDataDir = (PIMAGE_DATA_DIRECTORY)((PBYTE)pFileBuf + (DWORD)pDosHeader->e_lfanew + IMAGE_DATADIR_OFFSET);
	
	pReLoaction =(PIMAGE_BASE_RELOCATION)( RVAtoFOA((pDataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress, pFileBuf)+(LPBYTE)pFileBuf);
	if (pReLoaction->VirtualAddress == 0 && pReLoaction->SizeOfBlock == 0) return;

	PIMAGE_BASE_RELOCATION nextRelocatin = NULL;
	for (DWORD i = 0;; i++)
	{
		if (nextRelocatin != 0) pReLoaction = nextRelocatin;

		printf("============================================\n");
		printf("第%d个重定位表:%x\n",i+1, pReLoaction->VirtualAddress);

		LPWORD pReLoactionItem = (LPWORD)pReLoaction + 4;
		DWORD pReLoactionCount = (pReLoaction->SizeOfBlock - 8) >> 1;//需要修复的个数为整个块大小减去头再除以2

		for (DWORD i = 0; i < pReLoactionCount;i++)//输出高位为3的低12，再加上重定位表的rva等于真正要修复的地址W
		{
			if (pReLoactionItem[i] >> 12)
				//重定位表：01 30 -- 3001 -- 0011 0000 0000 0000    ，通过移位判断这个值=3，是有效值，继续输出，计算后的偏移=表的rva+（3001的低12位）
				printf("Index:%d,    重定位表中：%x    计算后的偏移：%x\n", i, pReLoactionItem[i], pReLoaction->VirtualAddress + (pReLoactionItem[i] & 0x0FFF));
		}
		//下一个表等于当前表+上当前的大小
		nextRelocatin = (PIMAGE_BASE_RELOCATION)(((DWORD)pReLoaction) + pReLoaction->SizeOfBlock);
		if (nextRelocatin->SizeOfBlock > pReLoaction->VirtualAddress||nextRelocatin->VirtualAddress==nextRelocatin->SizeOfBlock){
			break;
		}
	}

	tpSaveBufToFile(pFileBuf);
}

//测试移动重定位表到新节
VOID testMoveRelocationTableToNewSection()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpNewSection(pFileBuf);
	pFileBuf = tpmoveRelocation_Export_table(pFileBuf);
	tpSaveBufToFile(pFileBuf);
}

//测试同时移动重定位表和导出表
VOID testMoveRelocationAndExport_TABLE_ToNewSection()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpNewSection(pFileBuf);
	pFileBuf = tpmoveRelocation_Export_table(pFileBuf);
	tpSaveBufToFile(pFileBuf);
}

//测试修复重定位表
VOID testRepairRelocationTable()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpRepairRelocationTable(pFileBuf);
	tpSaveBufToFile(pFileBuf);

}