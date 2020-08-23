#include<stdio.h>
#include<Windows.h>


//SEH�ṹ
//typedef struct _EXCEPTION_REGISTRATION_RECORD {
//	struct _EXCEPTION_REGISTRATION_RECORD *Prev; //ָ��ǰһ��EXCEPTION_REGISTRATION��ָ��
//	PEXCEPTION_ROUTINE Handler; //��ǰ�쳣����ص������ĵ�ַ
//} EXCEPTION_REGISTRATION_RECORD;

//��SEH�ṹ
struct MyException
{
	struct MyException *prev;
	DWORD handle;
};

EXCEPTION_DISPOSITION _cdecl MyException_handler(
	PEXCEPTION_RECORD ExceptionRecord,
	void *EstablisherFrame,
	struct _CONTEXT *ContextRecord,
	void *DispatcherContext)
{

	PCHAR PEip;
	DWORD oldProtect = 0;
	DWORD newProtect = 0;

	printf("ExceptionCode:%x\n", ExceptionRecord->ExceptionCode);

	if (ExceptionRecord->ExceptionCode == 0x80000003)
	{
		PEip = (PCHAR)ContextRecord->Eip;
		printf("*PEip:%x\n", *PEip);
		if ((*PEip) == 0xffffffcc)
		{
			printf("��⵽�ϵ����!��Ҫ�޸�\n");
			if (!VirtualProtect(PEip, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				//MessageBox(NULL, "�������ڴ��д��Ȩ�޴���!", "��ʾ:", MB_OK);
				//CloseHandle(Phandle);
				return 0;
			}

			*PEip = 0x8b;

			////��ԭ���ڴ��д��Ȩ��
			if (!VirtualProtect(PEip, 1, oldProtect, &newProtect))
			{
				//MessageBox(NULL, "�ָ��ڴ��дȨ�޴���!", "��ʾ:", MB_OK);
				//CloseHandle(Phandle);
				return 0;
			}

			return ExceptionContinueExecution;
		}
	}
	return ExceptionContinueSearch;
}

void TestException()
{
	DWORD temp;
	//�����쳣 �����ڵ�ǰ�̵߳Ķ�ջ��
	struct MyException myException;
	__asm
	{
		mov eax, FS:[0]
		mov temp, eax
		lea ecx, myException
		mov FS : [0], ecx
	}

	myException.prev = (struct MyException*)temp;
	myException.handle = (DWORD)&MyException_handler;

	printf("Address of myException:%x\n", &myException);
	printf("Address of prev:%x\n", temp);

	//�����Ѿ����öϵ�ĺ���
	MessageBoxA(0, 0, 0, 0);

	//ժ���쳣
	__asm
	{
		mov eax, temp
		mov FS : [0], eax
	}

	printf("��������ִ����!\n");
}

void main()
{

	HMODULE hMoudle;
	DWORD dwLoadAddr = 0;
	PCHAR PHead = 0;
	DWORD oldProtect = 0;
	DWORD newProtect = 0;
	hMoudle = GetModuleHandle(TEXT("User32.dll"));

	dwLoadAddr = (DWORD)GetProcAddress(hMoudle, "MessageBoxA");
	printf("Address of MessageBoxA:%X\n", dwLoadAddr);
	PHead = (PCHAR)dwLoadAddr;

	if (!VirtualProtect(dwLoadAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		//MessageBox(NULL, "�������ڴ��д��Ȩ�޴���!", "��ʾ:", MB_OK);
		//CloseHandle(Phandle);
		return 0;
	}
	//��MessageBoxAͷ���¶ϵ�
	*PHead = 0xcc;

	////��ԭ���ڴ��д��Ȩ��
	if (!VirtualProtect(dwLoadAddr, 1, oldProtect, &newProtect))
	{
		//MessageBox(NULL, "�ָ��ڴ��дȨ�޴���!", "��ʾ:", MB_OK);
		//CloseHandle(Phandle);
		return 0;
	}


	TestException();
	getchar();





}