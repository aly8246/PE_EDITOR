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


//读取文件到fileBuf里，返回buffer
extern LPVOID tpReadFileToBuf();
//保存filebuf里修改好的数据到新的exe
extern LPVOID tpSaveBufToFile(LPVOID sFileBuf);

//拉伸filebuf到ImageBuf,返回ImgBuf
extern LPVOID tpFileBufToImgBuf(LPVOID pFileBuf);
//压缩ImageBuf到filebu,返回FileBuf
extern LPVOID tpImgbufToFileBuf(LPVOID pImgBuf);

extern DWORD RVAtoFOA(DWORD m_Rva, LPVOID pFileBuf);//ret foa
extern DWORD FOAtoRva(DWORD m_Foa, LPVOID pFileBuf);//ret rva

//清除PE头里的垃圾，有更多的空间添加一个新节
extern LPVOID tpCleanPeHeader(LPVOID pFileBuf);
//清除pe头垃圾并且添加一个新节
extern LPVOID tpNewSection(LPVOID pFileBuf);
//pe头清理垃圾也不够再添加一个新的节，只能扩大节
extern LPVOID tpExpSection(LPVOID pFileBuf);
//任意节添加测试代码
extern LPVOID tpSectionAddCode(LPVOID pFileBuf, char SectionID);

//移动导出表到新加节
extern LPVOID tpMoveExportTable(LPVOID pFileBuf);

//移动重定位表到新节
extern LPVOID tpMoveRelocationTable(LPVOID pFileBuf);

//移动导出表和重定位表
extern LPVOID tpmoveRelocation_Export_table(LPVOID pFileBuf);

//修复重定位表
extern LPVOID tpRepairRelocationTable(LPVOID pFileBuf);
#endif
