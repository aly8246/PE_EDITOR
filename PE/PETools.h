#ifndef PETOOLS_H_INCLUDE

#define LPVOID void*
#define LPBYTE char*
#define LPWORD short*
#define LPDWORD long*

#define FILEPATH "E:/1.dll"
#define NEWPATH "E:/new.dll"

#define IMAGE_SIZE_DOS_HEADER						64
#define IMAGE_DATADIR_OFFSET						0x78
#define IMAGE_SIZE_EXPORTTABLE						40

#define SectionNameLen 8
#define SectnionLen 0x6000
#define ExpandSection 0x10000

extern char readFilePath[];
extern char saveFilePath[];

extern LPVOID pFileBuf;
extern LPVOID pImgBuf;
extern DWORD sizeOfFile;

extern PIMAGE_DOS_HEADER pDosHeader;
extern PIMAGE_FILE_HEADER pPEHeader;
extern PIMAGE_OPTIONAL_HEADER pOptionHeader;
extern PIMAGE_SECTION_HEADER pSectionHeader;
extern PIMAGE_NT_HEADERS32 pNTHeader;

extern PIMAGE_DATA_DIRECTORY pDirCtory;

extern PIMAGE_EXPORT_DIRECTORY pExport;
extern PIMAGE_BASE_RELOCATION pReLoaction;
extern PIMAGE_IMPORT_DESCRIPTOR pImport;
extern PIMAGE_RESOURCE_DIRECTORY pResource;


//��ȡ�ļ���fileBuf�����buffer
extern LPVOID tpReadFileToBuf();
//����filebuf���޸ĺõ����ݵ��µ�exe
extern LPVOID tpSaveBufToFile(LPVOID sFileBuf);

//����filebuf��ImageBuf,����ImgBuf
extern LPVOID tpFileBufToImgBuf(LPVOID pFileBuf);
//ѹ��ImageBuf��filebu,����FileBuf
extern LPVOID tpImgbufToFileBuf(LPVOID pImgBuf);

extern DWORD RVAtoFOA(DWORD m_Rva, LPVOID pFileBuf);//ret foa
extern DWORD FOAtoRva(DWORD m_Foa, LPVOID pFileBuf);//ret rva

//���PEͷ����������и���Ŀռ����һ���½�
extern LPVOID tpCleanPeHeader(LPVOID pFileBuf);
//���peͷ�����������һ���½�
extern LPVOID tpNewSection(LPVOID pFileBuf);
//peͷ��������Ҳ���������һ���µĽڣ�ֻ�������
extern LPVOID tpExpSection(LPVOID pFileBuf);
//�������Ӳ��Դ���
extern LPVOID tpSectionAddCode(LPVOID pFileBuf, char SectionID);

//�ƶ��������¼ӽ�
extern LPVOID tpMoveExportTable(LPVOID pFileBuf);

//�ƶ��ض�λ���½�
extern LPVOID tpMoveRelocationTable(LPVOID pFileBuf);

//�ƶ���������ض�λ��
extern LPVOID tpmoveRelocation_Export_table(LPVOID pFileBuf);

//�޸��ض�λ��
extern LPVOID tpRepairRelocationTable(LPVOID pFileBuf);
#endif
