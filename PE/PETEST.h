#ifndef PETEST_H_INCLUDE

#define MESSAGEBOXADDR					0x7579F8B0      //本机MessAgeBox的地址，每次开机都不一样了      

#define SHELLCODELENGTH 0x12								//ShelloCode长度和内容


extern BYTE shellcode[];
extern BYTE SectionName[];

//打印pe头
extern LPVOID printfHeaderAndSection();

//测试拉伸
extern VOID testStretching();

//测试rva和foa的互相转换
extern VOID TEST_RVA_FOA();

//测试清理pe头垃圾
extern VOID testCleanPeHeader();
//测试清理pe头垃圾并且添加新节
extern VOID testNewSetion();
//测试扩大最后一个节
extern VOID	testExpSection();

//测试任意节 添加代码
extern VOID testSectionAddCode();

//打印导出表
extern VOID PrintfExportTable();

//测试移动导出表到新节
extern VOID testMoveExportTableToNewSection();

//打印重定位表
extern VOID PrintfRelocationTable();

//测试移动重定位表到新节
extern VOID testMoveRelocationTableToNewSection();

//测试同时移动重定位表和导出表
extern VOID testMoveRelocationAndExport_TABLE_ToNewSection();

//测试修复重定位表
extern VOID testRepairRelocationTable();
#endif
/************************************************************************/
/* 
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
                                                                     */
/************************************************************************/