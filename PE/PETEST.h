#ifndef PETEST_H_INCLUDE

#define MESSAGEBOXADDR					0x7579F8B0      //����MessAgeBox�ĵ�ַ��ÿ�ο�������һ����      

#define SHELLCODELENGTH 0x12								//ShelloCode���Ⱥ�����


extern BYTE shellcode[];
extern BYTE SectionName[];

//��ӡpeͷ
extern LPVOID printfHeaderAndSection();

//��������
extern VOID testStretching();

//����rva��foa�Ļ���ת��
extern VOID TEST_RVA_FOA();

//��������peͷ����
extern VOID testCleanPeHeader();
//��������peͷ������������½�
extern VOID testNewSetion();
//�����������һ����
extern VOID	testExpSection();

//��������� ��Ӵ���
extern VOID testSectionAddCode();

//��ӡ������
extern VOID PrintfExportTable();

//�����ƶ��������½�
extern VOID testMoveExportTableToNewSection();

//��ӡ�ض�λ��
extern VOID PrintfRelocationTable();

//�����ƶ��ض�λ���½�
extern VOID testMoveRelocationTableToNewSection();

//����ͬʱ�ƶ��ض�λ��͵�����
extern VOID testMoveRelocationAndExport_TABLE_ToNewSection();

//�����޸��ض�λ��
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