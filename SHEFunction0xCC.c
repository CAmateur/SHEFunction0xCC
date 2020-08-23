#include<stdio.h>
#include<Windows.h>


//SEH结构
//typedef struct _EXCEPTION_REGISTRATION_RECORD {
//	struct _EXCEPTION_REGISTRATION_RECORD *Prev; //指向前一个EXCEPTION_REGISTRATION的指针
//	PEXCEPTION_ROUTINE Handler; //当前异常处理回调函数的地址
//} EXCEPTION_REGISTRATION_RECORD;

//仿SEH结构
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
			printf("检测到断点存在!需要修复\n");
			if (!VirtualProtect(PEip, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				//MessageBox(NULL, "提升对内存读写的权限错误!", "提示:", MB_OK);
				//CloseHandle(Phandle);
				return 0;
			}

			*PEip = 0x8b;

			////还原对内存读写的权限
			if (!VirtualProtect(PEip, 1, oldProtect, &newProtect))
			{
				//MessageBox(NULL, "恢复内存读写权限错误!", "提示:", MB_OK);
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
	//插入异常 必须在当前线程的堆栈中
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

	//调用已经设置断点的函数
	MessageBoxA(0, 0, 0, 0);

	//摘掉异常
	__asm
	{
		mov eax, temp
		mov FS : [0], eax
	}

	printf("函数正常执行了!\n");
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
		//MessageBox(NULL, "提升对内存读写的权限错误!", "提示:", MB_OK);
		//CloseHandle(Phandle);
		return 0;
	}
	//对MessageBoxA头部下断点
	*PHead = 0xcc;

	////还原对内存读写的权限
	if (!VirtualProtect(dwLoadAddr, 1, oldProtect, &newProtect))
	{
		//MessageBox(NULL, "恢复内存读写权限错误!", "提示:", MB_OK);
		//CloseHandle(Phandle);
		return 0;
	}


	TestException();
	getchar();





}