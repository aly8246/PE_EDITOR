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

//��ӡpeͷ
LPVOID printfHeaderAndSection()
{
	pFileBuf = tpReadFileToBuf();
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��");
		free(pFileBuf);
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	if (*((PWORD)pFileBuf) != IMAGE_DOS_SIGNATURE){
		printf("������Ч��win32Ӧ�ó���"); return NULL;
	}
	printf("************DOSͷ************************************************\n");
	printf("MZƫ��: %x\n", pDosHeader->e_magic);
	printf("e_cblp      �ļ����ҳ������:%x\n", pDosHeader->e_cblp);
	printf("e_cp        �ļ�ҳ��:%x\n", pDosHeader->e_cp);
	printf("e_crlc      �ض���Ԫ�ظ���:%x\n", pDosHeader->e_crlc);
	printf("e_cparhdr   ͷ���ߴ磬�Զ���Ϊ��λ:%x\n", pDosHeader->e_cparhdr);
	printf("e_minalloc  ������С���Ӷ�:%x\n", pDosHeader->e_minalloc);
	printf("e_maxalloc  ������󸽼Ӷ�:%x\n", pDosHeader->e_maxalloc);
	printf("e_ss        DOS�������SS:%x\n", pDosHeader->e_ss);
	printf("e_sp        DOS�������SP:%x\n", pDosHeader->e_sp);
	printf("e_csum      У���:%x\n", pDosHeader->e_csum);
	printf("e_cs        DOS�������CS:%x\n", pDosHeader->e_cs);
	printf("e_ip        DOS�������IP:%x\n", pDosHeader->e_ip);
	printf("e_lfarlc    �ط�����ļ���ַ:%x\n", pDosHeader->e_lfarlc);
	printf("e_ovno      ���Ǻ�:%x\n", pDosHeader->e_ovno);
	printf("e_res[4]    ������:%x\n", pDosHeader->e_res[0]);
	printf("e_oemid     OEM��ʶ��[���e_oeminfo]:%x\n", pDosHeader->e_oemid);
	printf("e_oeminfo   OEM��Ϣ:%x\n", pDosHeader->e_oeminfo);
	printf("e_res2[10]  ������2:%x\n", pDosHeader->e_res2[0]);
	printf("e_lfanew    PEƫ��:%x\n", pDosHeader->e_lfanew);
	printf("************NTͷ************\n");
	printf("NTsignature:						 %x-%x\n", (DWORD)&(pNTHeader->Signature), pNTHeader->Signature);
	printf("NT-FileHeader:						 %x\n", pNTHeader->FileHeader);
	printf("************NTͷ_��׼peͷ****************************************************\n");
	printf("Machine			    ��������ƽ̨:%x\n", pPEHeader->Machine);
	printf("NumberOfSecions		�ڱ����Ŀ:%x\n", pPEHeader->NumberOfSections);
	printf("TimeDateStamp		�ļ�������ʱ���:%x\n", pPEHeader->TimeDateStamp);
	printf("PointOfSymbolTable  ָ����ű����ڵ��ԣ�:%x\n", pPEHeader->PointerToSymbolTable);
	printf("NumberOfSymbols     ���ű��еĸ��������ڵ��ԣ�:%x\n", pPEHeader->NumberOfSymbols);
	printf("SizeOfOptionHeaders ��ѡpeͷ�ĳ���:%x\n", pPEHeader->SizeOfOptionalHeader);
	printf("Charteristics	    ����ֵ/�ļ���Ϣ��־:			%x\n", pPEHeader->Characteristics);
	//��ѡpeͷ=
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("************NTͷ_��ѡpeͷ****************************************************\n");
	printf("Magic				        ��־�֣�������,��ֵΪ\"10Bh\"%x\n", pOptionHeader->Magic);
	printf("MajorLinkerVersion			���������汾��%x\n", pOptionHeader->MajorLinkerVersion);
	printf("MinorLinkerVersion			�������ΰ汾��%x\n", pOptionHeader->MinorLinkerVersion);
	printf("SizeOfCode					����δ�С%x\n", pOptionHeader->SizeOfCode);
	printf("SizeOfInitializedDate		�ѳ�ʼ�����ݿ��С%x\n", pOptionHeader->SizeOfInitializedData);
	printf("sizeOfUninitializedDate		δ��ʼ�����ݿ��С%x\n", pOptionHeader->SizeOfUninitializedData);
	printf("AddressEntryPoint(RVA)		����ִ�е���ڣ�RVA%x\n", pOptionHeader->AddressOfEntryPoint);
	printf("BaseOfCode					�������ʼ��ַ%x\n", pOptionHeader->BaseOfCode);
	printf("BaseOfDate					���ݿ���ʼ��ַ%x\n", pOptionHeader->BaseOfData);
	printf("ImageBase					�����ַ%x\n", pOptionHeader->ImageBase);
	printf("SectionAlignment			�ڴ����%x\n", pOptionHeader->SectionAlignment);
	printf("FileAlignment				�ļ�����%x\n", pOptionHeader->FileAlignment);
	printf("MajorOperatingSystemVersion ����ϵͳ���汾��%x\n", pOptionHeader->MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion ����ϵͳ�ΰ汾��%x\n", pOptionHeader->MinorOperatingSystemVersion);
	printf("MajorImageVersion			��ִ���ļ������汾�ţ��Զ���%x\n", pOptionHeader->MajorImageVersion);
	printf("MinorImageVersion			��ִ���ļ��Ĵΰ汾�ţ��Զ���%x\n", pOptionHeader->MinorImageVersion);
	printf("MajorSubsystemVersion		��ϵͳ���汾��%x\n", pOptionHeader->MajorSubsystemVersion);
	printf("MinorSubsystemVersion		��ϵͳ�ΰ汾��%x\n", pOptionHeader->MinorSubsystemVersion);
	printf("Win32VersionValue			����������\"00000000\"%x\n", pOptionHeader->Win32VersionValue);
	printf("SizeOfImage					����pe�ļ�װ�ں�ľ����С%x\n", pOptionHeader->SizeOfImage);
	printf("SizeOfHeader				PEͷ�ͽڱ�Ĵ�С%x\n", pOptionHeader->SizeOfHeaders);
	printf("CheckSum					CRCУ���%x\n", pOptionHeader->CheckSum);
	printf("Subsystem					��ϵͳ:����̨/�ַ�%x\n", pOptionHeader->Subsystem);
	printf("DllCharacteristics			DllMain()��ʱ������%x\n", pOptionHeader->DllCharacteristics);
	printf("SizeOfStackReserve			��ʼ��ʱΪ�̱߳�����ջ��С%x\n", pOptionHeader->SizeOfStackReserve);
	printf("SizeOfStackCommint			��ʼ��ʱ�߳�ʵ��ʹ��ջ��С%x\n", pOptionHeader->SizeOfStackCommit);
	printf("SizeOfHeapReserve			��ʼ��ʱΪ���̱����ĶѴ�С%x\n", pOptionHeader->SizeOfHeapReserve);
	printf("SizeOfHeapCommint			��ʼ��ʱ����ʵ��ʹ�öѴ�С%x\n", pOptionHeader->SizeOfHeapCommit);
	printf("LoderFlages					�����Զ����öϵ�������%x\n", pOptionHeader->LoaderFlags);
	printf("NumberOfRvaAndSize			����Ŀ¼�ṹ����������10h%x\n", pOptionHeader->NumberOfRvaAndSizes);

	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		//�����һ���ڱ��λ��
		pSectionHeader += i;
		printf("************��%d�ڱ�************\n", i + 1);
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
		printf(" �ڱ�����: %x-------%s\n", (DWORD)&(pSectionHeader->Name), pSectionHeader->Name);
		printf(" VirtualAddress: %x-------%x\n", (DWORD)&(pSectionHeader->VirtualAddress), pSectionHeader->VirtualAddress);
		printf(" PointerToRawData: %x-------%x\n", (DWORD)&(pSectionHeader->PointerToRawData), pSectionHeader->PointerToRawData);
	}

	tpSaveBufToFile(pFileBuf);
	return 0;
}

//��������
VOID testStretching()
{
	pFileBuf=tpReadFileToBuf();
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��");
		free(pFileBuf);
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	if (*((PWORD)pFileBuf) != IMAGE_DOS_SIGNATURE){
		printf("������Ч��win32Ӧ�ó���");
	}
	pImgBuf=tpFileBufToImgBuf(pFileBuf);
	pFileBuf = tpImgbufToFileBuf(pImgBuf);

	tpSaveBufToFile(pFileBuf);
}

//����rva��foa�Ļ���ת��
VOID TEST_RVA_FOA()
{
	pFileBuf = tpReadFileToBuf();
	DWORD Rva1 = (DWORD)0x9001;
	DWORD Foa1 = NULL;
	DWORD Rva2 = NULL;
	DWORD Foa2 = (DWORD)0x7801;

	Foa1 = RVAtoFOA(Rva1, pFileBuf);
	printf("�����ַ��Ӧ��foa��%x\n", Foa1);

	Rva2 = FOAtoRva(Foa2, pFileBuf);
	printf("�����ַ��Ӧ��rva��%x\n", Rva2);
}

//��������peͷ����
extern VOID testCleanPeHeader()
{
	pFileBuf = tpReadFileToBuf();
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��");
		free(pFileBuf);
	}
	pFileBuf=tpCleanPeHeader(pFileBuf);
	tpSaveBufToFile(pFileBuf);
}

//��������peͷ������������½�
VOID testNewSetion()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpNewSection(pFileBuf);
	tpSaveBufToFile(pFileBuf);
}
//�����������һ����
VOID	testExpSection()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpExpSection(pFileBuf);
	tpSaveBufToFile(pFileBuf);
}

//��������� ��Ӵ���
VOID testSectionAddCode()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpExpSection(pFileBuf);
	pFileBuf = tpSectionAddCode(pFileBuf, 0);
	tpSaveBufToFile(pFileBuf);
}

//��ӡ������
VOID PrintfExportTable()
{
	pFileBuf = tpReadFileToBuf();
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��");
	}

	pFileBuf = tpCleanPeHeader(pFileBuf);

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	if (*((PWORD)pFileBuf) != IMAGE_DOS_SIGNATURE){
		printf("������Ч��win32Ӧ�ó���");
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
	printf("ʱ���----------------------%d---------\n", pExport->TimeDateStamp);
	LPDWORD pName = (LPDWORD)((DWORD)RVAtoFOA(pExport->Name, pFileBuf) + (LPBYTE)pFileBuf);
	printf("ָ��õ����������ַ���------%s---------\n", pName);
	printf("������������ʼ���----------%d---------\n", pExport->Base);
	printf("���е��������ĸ���----------%d---------\n", pExport->NumberOfFunctions);
	printf("���ֵ��������ĸ���----------%d---------\n", pExport->NumberOfNames);
	printf("====================================================================\n");

	for (DWORD i = 0; i < pExport->NumberOfNames;i++)
	{
		funNameIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf) + i;
		funName = RVAtoFOA(*funNameIndex, pFileBuf) + (LPBYTE)pFileBuf;

		funOrdinalsIndex = (LPWORD)(RVAtoFOA(pExport->AddressOfNameOrdinals, pFileBuf) + (LPBYTE)pFileBuf) + i;
		funOrdinals = (DWORD)*funOrdinalsIndex;

		funAddrIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfFunctions, pFileBuf) + (LPBYTE)pFileBuf) + funOrdinals;
		funAddr=(DWORD)*funAddrIndex;

		
		printf("��������:%s---���ֱ��е�FOA:%x---�������:%x---��ű��е�FOA:%x---������ַ%x---��ַ���е�FOA:%x:\n", 
			funName, funNameIndex - (LPDWORD)pFileBuf,
				funOrdinals + pExport->Base, funOrdinalsIndex - (LPWORD)pFileBuf,
				funAddr,funAddrIndex-(LPDWORD)pFileBuf
				);
	}

	tpSaveBufToFile(pFileBuf);

	//pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pFileBuf+RVAtoFOA())	IMAGE_DIRECTORY_ENTRY_EXPORT

}

//�����ƶ��������½�
VOID testMoveExportTableToNewSection()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpNewSection(pFileBuf);

	pFileBuf = tpMoveExportTable(pFileBuf);

	tpSaveBufToFile(pFileBuf);
}

//��ӡ�ض�λ��
VOID PrintfRelocationTable()
{
	pFileBuf = tpReadFileToBuf();
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��");
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
		printf("��%d���ض�λ��:%x\n",i+1, pReLoaction->VirtualAddress);

		LPWORD pReLoactionItem = (LPWORD)pReLoaction + 4;
		DWORD pReLoactionCount = (pReLoaction->SizeOfBlock - 8) >> 1;//��Ҫ�޸��ĸ���Ϊ�������С��ȥͷ�ٳ���2

		for (DWORD i = 0; i < pReLoactionCount;i++)//�����λΪ3�ĵ�12���ټ����ض�λ���rva��������Ҫ�޸��ĵ�ַW
		{
			if (pReLoactionItem[i] >> 12)
				//�ض�λ��01 30 -- 3001 -- 0011 0000 0000 0000    ��ͨ����λ�ж����ֵ=3������Чֵ�����������������ƫ��=���rva+��3001�ĵ�12λ��
				printf("Index:%d,    �ض�λ���У�%x    ������ƫ�ƣ�%x\n", i, pReLoactionItem[i], pReLoaction->VirtualAddress + (pReLoactionItem[i] & 0x0FFF));
		}
		//��һ������ڵ�ǰ��+�ϵ�ǰ�Ĵ�С
		nextRelocatin = (PIMAGE_BASE_RELOCATION)(((DWORD)pReLoaction) + pReLoaction->SizeOfBlock);
		if (nextRelocatin->SizeOfBlock > pReLoaction->VirtualAddress||nextRelocatin->VirtualAddress==nextRelocatin->SizeOfBlock){
			break;
		}
	}

	tpSaveBufToFile(pFileBuf);
}

//�����ƶ��ض�λ���½�
VOID testMoveRelocationTableToNewSection()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpNewSection(pFileBuf);
	pFileBuf = tpmoveRelocation_Export_table(pFileBuf);
	tpSaveBufToFile(pFileBuf);
}

//����ͬʱ�ƶ��ض�λ��͵�����
VOID testMoveRelocationAndExport_TABLE_ToNewSection()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpNewSection(pFileBuf);
	pFileBuf = tpmoveRelocation_Export_table(pFileBuf);
	tpSaveBufToFile(pFileBuf);
}

//�����޸��ض�λ��
VOID testRepairRelocationTable()
{
	pFileBuf = tpReadFileToBuf();
	pFileBuf = tpRepairRelocationTable(pFileBuf);
	tpSaveBufToFile(pFileBuf);

}