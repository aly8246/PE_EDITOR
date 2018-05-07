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


//��ȡ�ļ���fileBuf�����buffer
LPVOID tpReadFileToBuf()
{
	FILE* fp = fopen(readFilePath, "rb+");
	if (!fp)
	{
		printf("�ļ���ʧ�ܣ�");
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
		printf("���仺����ʧ��");
		system("pause");
		fclose(fp);
		free(pFileBuf);
	}

	size_t n = fread(pFileBuf, sizeOfFile, 1, fp);
	if (!n)
	{
		printf("���仺����ʧ��");
		system("pause");
		fclose(fp);
		free(pFileBuf);
	}

	fclose(fp);


	return pFileBuf;
}
//����filebuf���޸ĺõ����ݵ��µ�exe
LPVOID tpSaveBufToFile(LPVOID sFileBuf)
{
	if (!sFileBuf)
	{
		printf("û����ȷ��дfileBuf!"); system("pause"); return NULL;
	}

	FILE* fp = fopen(SaveFilePath, "wb");
	fwrite(sFileBuf, sizeof(sFileBuf), sizeOfFile / 4, fp);

	fclose(fp);
	free(pFileBuf);

	printf("���̳ɹ���\n");
	Sleep(1500);
	return 0;
}


//����filebuf��ImageBuf
LPVOID tpFileBufToImgBuf(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��"); 
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
//ѹ��ImageBuf��filebu
LPVOID tpImgbufToFileBuf(LPVOID pImgBuf)
{
	if (!pImgBuf)
	{
		printf("��ȡ�ļ�ʧ��");
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
		printf("��ȡ�ļ�ʧ��");
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
			){//��� rvaС��peͷ���ߴ���imagebase˵������ҪRVAtoFOA,��� filebuf���ڴ������ļ�����һ��Ҳ����Ҫ
			return m_Rva;
			break;
		}
		fSeciton = m_Rva;
	}

	//�ļ�ƫ��=Rva��Ե�ַƫ�Ƽ�ȥ�ýڵ�rva+�õ�ַ���ڽڵ�����ƫ��
	m_Foa = m_Rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;

	return m_Foa;
}
DWORD FOAtoRva(DWORD m_Foa, LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��");
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
			){//��� rvaС��peͷ���ߴ���imagebase˵������ҪRVAtoFOA,��� filebuf���ڴ������ļ�����һ��Ҳ����Ҫ
			return m_Foa;
			break;
		}
		fSeciton = m_Foa;
	}

	//�ļ�ƫ��=Rva��Ե�ַƫ�Ƽ�ȥ�ýڵ�rva+�õ�ַ���ڽڵ�����ƫ��
	m_Rva = m_Foa - pSectionHeader->PointerToRawData + pSectionHeader->VirtualAddress;
	return m_Rva;
}


//���PEͷ����������и���Ŀռ����һ���½�
LPVOID tpCleanPeHeader(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��");
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
	//�ڱ���ʼλ��=dosͷ��С+��Ǵ�С0x4+fileͷ��С+optinalͷ��С
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
//���peͷ�����������һ���½�
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
//peͷ��������Ҳ���������һ���µĽڣ�ֻ�������
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

//�������Ӳ��Դ���
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
		printf("��ѡ��Ľڲ����ڣ����ֻ��%d%����", pPEHeader->NumberOfSections);
		return false;
	}
	else if (pSectionHeader->Misc.VirtualSize > pSectionHeader->SizeOfRawData)
	{
		printf("�˽ڵĿհ����򲻹���Ӵ���");
		return false;
	}

	LPBYTE CodeBegin = (LPBYTE)pFileBuf + RVAtoFOA(pSectionHeader->VirtualAddress, pFileBuf);
	memcpy(CodeBegin, shellcode, SHELLCODELENGTH);

	//e8 CALL��ƫ�Ƶ�ַ=MessageBox��ַ  - (ImageBase           +   �Լ���oep  +  e8��һ��ָ��ĵ�ַ -  �ļ�����)
	DWORD callAddr = MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((DWORD)CodeBegin + 0xD - (DWORD)pFileBuf));
	//e9 JMP��ƫ�Ƶ�ַ=ԭ����oep  -  (�Լ���oep   +   e9��һ�е�ַ -  �ļ�����)
	DWORD jmpAddr = pOptionHeader->AddressOfEntryPoint - ((DWORD)CodeBegin + 0x12 - (DWORD)pFileBuf);

	*(DWORD*)(CodeBegin + 0x9) = callAddr;
	*(DWORD*)(CodeBegin + 0xE) = jmpAddr;

	pOptionHeader->AddressOfEntryPoint = (DWORD)CodeBegin - (DWORD)pFileBuf;

	DWORD x = pSectionHeader->Characteristics;
	DWORD y = (pSectionHeader-pPEHeader->NumberOfSections+1)->Characteristics;
	pSectionHeader->Characteristics = x | y;

	return pFileBuf;
}

//�ƶ��������¼ӽ�
LPVOID tpMoveExportTable(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//����½���ɳ�ʼ���������õ�foa
	PIMAGE_SECTION_HEADER pEndSection = pSectionHeader + pPEHeader->NumberOfSections - 1;
	LPBYTE nExportBegin = (LPBYTE)pFileBuf + (DWORD)pEndSection->PointerToRawData;

	//������
	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	pDataDir = (PIMAGE_DATA_DIRECTORY)((PBYTE)pFileBuf + (DWORD)pDosHeader->e_lfanew + IMAGE_DATADIR_OFFSET);
	if (pDataDir->VirtualAddress == 0 && pDataDir->Size == 0) return false;

	pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pFileBuf + RVAtoFOA((pDataDir + IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress, pFileBuf));
	
	/************************************************************************//* 
	��ʼ����Ҫ�ƶ���С��ָ��
	�õ�ԭ����С��ĵ�ַָ��
	��ԭ���ı��Ƶ��µ�ַ��
	�޸�������ĵ�ַ����ȷ��
	������һ�����Դ�ŵĵ�ַ
	*//************************************************************************/



	//׼����ʼ�ƶ����������ƶ�������ַ��,�޸��������AddressOfFunctions,������һ���ڿ���λ��
	LPDWORD funAddrIndex = NULL;
	funAddrIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfFunctions, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportBegin, funAddrIndex, 4 * pExport->NumberOfFunctions);
	pExport->AddressOfFunctions = FOAtoRva((DWORD)nExportBegin - (DWORD)pFileBuf, pFileBuf);
	LPBYTE nExportNext = (LPBYTE)pFileBuf + (DWORD)pEndSection->PointerToRawData + 4 * pExport->NumberOfFunctions;

	printf("�µĺ�����ַ���RVA��0x%x------�µĺ�����ַ���FOA:0x%x\n", pExport->AddressOfFunctions, (DWORD)nExportNext - (DWORD)pFileBuf);


	//�ƶ���ű���ַ��ĺ��棬�޸��������AddressOfNameOrdinals,������һ���ڿ���λ��
	LPWORD funOrdinalsIndex = NULL;
	funOrdinalsIndex = (LPWORD)(RVAtoFOA(pExport->AddressOfNameOrdinals, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportNext, funOrdinalsIndex, 2 * pExport->NumberOfNames);
	pExport->AddressOfNameOrdinals = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	nExportNext += 2 * pExport->NumberOfNames;

	printf("�µĺ�����ű��RVA��0x%x------�µĺ�����ű��FOA:0x%x\n", pExport->AddressOfNameOrdinals, (DWORD)nExportNext - (DWORD)pFileBuf);

	//�ƶ����ֱ���ĵ�ַ���ֵ����̬������һ����ַ������ֱ���޸����ֱ���ĵ�ַ��Ȼ��ֱ���ƶ����ֱ�
	LPDWORD funNameIndex = NULL;
	LPDWORD funNameNext =(LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf);
	LPBYTE funName = NULL;

	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		funNameIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf)+i;
		funName = RVAtoFOA(*funNameIndex, pFileBuf) + (LPBYTE)pFileBuf;

		memcpy(nExportNext, funName, strlen(funName)+1);//������i�����������µ�ַ

	
		funNameNext[i] = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);

		nExportNext += strlen(funName)+1;
	}

	funNameIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportNext, funNameIndex, 4 * pExport->NumberOfNames);
	pExport->AddressOfNames = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	nExportNext += 4 * pExport->NumberOfNames;

	printf("�µĺ������Ʊ��RVA��0x%x------�µĺ������Ʊ��FOA:0x%x\n", pExport->AddressOfNames, (DWORD)nExportNext - (DWORD)pFileBuf);

	//����ƶ�����������ṹ������Ŀ¼�ṹ��ָ���µĵ�����ṹ
	memcpy(nExportNext, pExport, IMAGE_SIZE_EXPORTTABLE);
	pDataDir->VirtualAddress = FOAtoRva((DWORD)nExportNext-(DWORD)pFileBuf, pFileBuf);
	printf("�µĵ������RVA��0x%x-----�µĵ������FOA��0x%x\n", pDataDir->VirtualAddress, (DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);

	return pFileBuf;
}

//�ƶ��ض�λ���½�
LPVOID tpMoveRelocationTable(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��");
		return false;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER pEndSection = pSectionHeader + pPEHeader->NumberOfSections - 1;
	LPBYTE nRelocationNext = (LPBYTE)pFileBuf + (DWORD)pEndSection->PointerToRawData;//��һ���½��е��ض�λ��


	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	pDataDir = (PIMAGE_DATA_DIRECTORY)((PBYTE)pFileBuf + (DWORD)pDosHeader->e_lfanew + IMAGE_DATADIR_OFFSET);

	pReLoaction = (PIMAGE_BASE_RELOCATION)(RVAtoFOA((pDataDir + IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress, pFileBuf) + (LPBYTE)pFileBuf);
	if (pReLoaction->VirtualAddress == 0 && pReLoaction->SizeOfBlock == 0) return false;

	PIMAGE_BASE_RELOCATION nextRelocatin = NULL;//��һ���ض�λ��

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

//�ƶ���������ض�λ��
LPVOID tpmoveRelocation_Export_table(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + (pDosHeader->e_lfanew));
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//����½���ɳ�ʼ���������õ�foa
	PIMAGE_SECTION_HEADER pEndSection = pSectionHeader + pPEHeader->NumberOfSections - 1;
	LPBYTE nExportBegin = (LPBYTE)pFileBuf + (DWORD)pEndSection->PointerToRawData;

	//������
	PIMAGE_DATA_DIRECTORY pDataDir = NULL;
	pDataDir = (PIMAGE_DATA_DIRECTORY)((PBYTE)pFileBuf + (DWORD)pDosHeader->e_lfanew + IMAGE_DATADIR_OFFSET);
	if (pDataDir->VirtualAddress == 0 && pDataDir->Size == 0) return false;

	pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pFileBuf + RVAtoFOA((pDataDir + IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress, pFileBuf));

	/************************************************************************//*
	��ʼ����Ҫ�ƶ���С��ָ��
	�õ�ԭ����С��ĵ�ַָ��
	��ԭ���ı��Ƶ��µ�ַ��
	�޸�������ĵ�ַ����ȷ��
	������һ�����Դ�ŵĵ�ַ
	*//************************************************************************/



	//׼����ʼ�ƶ����������ƶ�������ַ��,�޸��������AddressOfFunctions,������һ���ڿ���λ��
	LPDWORD funAddrIndex = NULL;
	funAddrIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfFunctions, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportBegin, funAddrIndex, 4 * pExport->NumberOfFunctions);
	pExport->AddressOfFunctions = FOAtoRva((DWORD)nExportBegin - (DWORD)pFileBuf, pFileBuf);
	LPBYTE nExportNext = (LPBYTE)pFileBuf + (DWORD)pEndSection->PointerToRawData + 4 * pExport->NumberOfFunctions;

	printf("�µĺ�����ַ���RVA��0x%x------�µĺ�����ַ���FOA:0x%x\n", pExport->AddressOfFunctions, (DWORD)nExportNext - (DWORD)pFileBuf);


	//�ƶ���ű���ַ��ĺ��棬�޸��������AddressOfNameOrdinals,������һ���ڿ���λ��
	LPWORD funOrdinalsIndex = NULL;
	funOrdinalsIndex = (LPWORD)(RVAtoFOA(pExport->AddressOfNameOrdinals, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportNext, funOrdinalsIndex, 2 * pExport->NumberOfNames);
	pExport->AddressOfNameOrdinals = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	nExportNext += 2 * pExport->NumberOfNames;

	printf("�µĺ�����ű��RVA��0x%x------�µĺ�����ű��FOA:0x%x\n", pExport->AddressOfNameOrdinals, (DWORD)nExportNext - (DWORD)pFileBuf);

	//�ƶ����ֱ���ĵ�ַ���ֵ����̬������һ����ַ������ֱ���޸����ֱ���ĵ�ַ��Ȼ��ֱ���ƶ����ֱ�
	LPDWORD funNameIndex = NULL;
	LPDWORD funNameNext = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf);
	LPBYTE funName = NULL;

	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		funNameIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf) + i;
		funName = RVAtoFOA(*funNameIndex, pFileBuf) + (LPBYTE)pFileBuf;

		memcpy(nExportNext, funName, strlen(funName) + 1);//������i�����������µ�ַ


		funNameNext[i] = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);

		nExportNext += strlen(funName) + 1;
	}

	funNameIndex = (LPDWORD)(RVAtoFOA(pExport->AddressOfNames, pFileBuf) + (LPBYTE)pFileBuf);
	memcpy(nExportNext, funNameIndex, 4 * pExport->NumberOfNames);
	pExport->AddressOfNames = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	nExportNext += 4 * pExport->NumberOfNames;

	printf("�µĺ������Ʊ��RVA��0x%x------�µĺ������Ʊ��FOA:0x%x\n", pExport->AddressOfNames, (DWORD)nExportNext - (DWORD)pFileBuf);

	//����ƶ�����������ṹ������Ŀ¼�ṹ��ָ���µĵ�����ṹ
	memcpy(nExportNext, pExport, IMAGE_SIZE_EXPORTTABLE);
	pDataDir->VirtualAddress = FOAtoRva((DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	printf("�µĵ������RVA��0x%x-----�µĵ������FOA��0x%x\n", pDataDir->VirtualAddress, (DWORD)nExportNext - (DWORD)pFileBuf, pFileBuf);
	//���������λ��=
	nExportNext += IMAGE_SIZE_EXPORTTABLE;



	/************************************************************************/
	/*					���ض�λ����ʼλ���ǵ��������λ��                  */
	/************************************************************************/
	//�ƶ��ض�λ���±�ʼ��λ��Ϊ�����������λ��
	LPBYTE nRelocationNext = nExportNext;//��һ���½��е��ض�λ��
	PIMAGE_BASE_RELOCATION nextRelocatin = NULL;//��һ���ض�λ��

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

//�޸��ض�λ��
LPVOID tpRepairRelocationTable(LPVOID pFileBuf)
{
	if (!pFileBuf)
	{
		printf("��ȡ�ļ�ʧ��");
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

	//����ԭ����imagebase��10000000�����ڴ��б����20000000
	DWORD oldImageBase = 0x10000000;
	pOptionHeader->ImageBase = 0x20000000;
	DWORD newImageBase = pOptionHeader->ImageBase;



	PIMAGE_BASE_RELOCATION nextRelocatin = NULL;
	for (DWORD i = 0;; i++)
	{
		if (nextRelocatin != 0) pReLoaction = nextRelocatin;

		printf("============================================\n");
		printf("��%d���ض�λ��:%x\n", i + 1, pReLoaction->VirtualAddress);

		LPWORD pReLoactionItem = (LPWORD)pReLoaction + 4;
		DWORD pReLoactionCount = (pReLoaction->SizeOfBlock - 8) >> 1;//��Ҫ�޸��ĸ���Ϊ�������С��ȥͷ�ٳ���2

		for (DWORD i = 0; i < pReLoactionCount; i++)//�����λΪ3�ĵ�12���ټ����ض�λ���rva��������Ҫ�޸��ĵ�ַW
		{
			if (pReLoactionItem[i] >> 12)
				//�ض�λ��01 30 -- 3001 -- 0011 0000 0000 0000    ��ͨ����λ�ж����ֵ=3������Чֵ�����������������ƫ��=���rva+��3001�ĵ�12λ��
				printf("Index:%d,    �ض�λ���У�%x    ������ƫ�ƣ�%x\n", i, pReLoactionItem[i], pReLoaction->VirtualAddress + (pReLoactionItem[i] & 0x0FFF));

				LPDWORD pImage_RepairRelocation = NULL;//��Ҫ�޸��ĵ�һ����ַ��418+filebuffer
				pImage_RepairRelocation =(LPDWORD)(RVAtoFOA(pReLoaction->VirtualAddress + (pReLoactionItem[i] & 0x0FFF), pFileBuf)+(LPBYTE)pFileBuf);
				*pImage_RepairRelocation += newImageBase - oldImageBase;//�õ��ض�λ�����ֵ���жϸ�12λ�Ƿ���Ҫ�޸������õ���12λ����������ε�rva��������Ҫ�޸���rva��
																		//ת����foa��ȡ��ַ�����ֵȫ�����ϲ�ֵ,�ض�λ���޸����
		}
		//��һ������ڵ�ǰ��+�ϵ�ǰ�Ĵ�С
		nextRelocatin = (PIMAGE_BASE_RELOCATION)(((DWORD)pReLoaction) + pReLoaction->SizeOfBlock);
		if (nextRelocatin->SizeOfBlock > pReLoaction->VirtualAddress || nextRelocatin->VirtualAddress == nextRelocatin->SizeOfBlock){
			break;
		}
	}


	return pFileBuf;
}