#include "InjectDll.h"
using namespace std;

//判断是否为64位系统
bool InjectDll::is64BitOS()
{
	SYSTEM_INFO cur_system_info;
	GetNativeSystemInfo(&cur_system_info);
	WORD system_str = cur_system_info.wProcessorArchitecture;
	//判断是否为64位系统
	if (system_str == PROCESSOR_ARCHITECTURE_IA64 || system_str == PROCESSOR_ARCHITECTURE_AMD64)
	{
		return true;
	}
	return false;
}

//判断是否为64位进程
//@param:进程id
/*
Parameters
hProcess
A handle to the process. The handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right. For more information, see Process Security and Access Rights.
Windows Server 2003 and Windows XP:  The handle must have the PROCESS_QUERY_INFORMATION access right.
Wow64Process
A pointer to a value that is set to TRUE if the process is running under WOW64 on an Intel64 or x64 processor. If the process is running under 32-bit Windows, the value is set to FALSE. If the process is a 32-bit application running under 64-bit Windows 10 on ARM, the value is set to FALSE. If the process is a 64-bit application running under 64-bit Windows, the value is also set to FALSE.
*/
bool InjectDll::is64BitProcess(DWORD dwPid)
{
	if (!is64BitOS())
	{
		cout << "is 32 Bit OS";
		return false;
	}

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
	if (hProcess)
	{
		typedef BOOL(WINAPI * LPEN_ISWOW64PROCESS)(HANDLE, PBOOL);
		LPEN_ISWOW64PROCESS fnlsWow64Process = (LPEN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");
		if (NULL != fnlsWow64Process)
		{
			BOOL bIsWow64 = FALSE;
			fnlsWow64Process(hProcess, &bIsWow64);
			CloseHandle(hProcess);
			return !bIsWow64;
		}
	}
	return false;
}

//Inject32ToDll
//Params: 程序标题,dll名称
bool InjectDll::TestInjectDll(LPCWSTR wins_title, const char* dllName)
{
	HWND hWnd = FindWindow(NULL, wins_title); //获得该程序的句柄
	if (hWnd == nullptr)
	{
		cout << "当前程序不存在" << endl;
		return false;
	}
	DWORD dwPid;
	DWORD dwThreadId = GetWindowThreadProcessId(hWnd, &dwPid); //dwThreadId:当前程序的线程ID，dwPid:当前程序的进程Pid
	bool flag_process = is64BitProcess(dwPid); //判断是否为64位程序
	if (flag_process)//64位程序时
	{
		inject64Process(dwPid, dllName);
	}
	else //32位程序时
	{
		inject32Process(dwPid, dllName);
	}
	return true;
}

//注入32位程序
bool InjectDll::inject32Process(DWORD dwPid, const char* dllName)
{
	//1.打开对应进程，获取该进程的句柄
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |  
		PROCESS_CREATE_THREAD |   
		PROCESS_VM_OPERATION |  
		PROCESS_VM_WRITE,         
		FALSE, dwPid);//打开对应进程
	if (hProcess == NULL)
	{
		return INJECT_ERROR;
	}

	//2.分配内存，用堆分配
	LPBYTE currentAddress = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);
	if (NULL == currentAddress)
	{
		return INJECT_ERROR;
	}

	//3.在指定的虚拟空间保留内存
	LPVOID targetWorkspace = VirtualAllocEx(hProcess, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //在进程的虚拟空间保留或提交内存区域，返回值为分配区域的地址
		//判断分配是否成功
	if (NULL == targetWorkspace)
	{
		return INJECT_ERROR;
	}

	DWORD targetAddress = PtrToUlong(targetWorkspace); //地址转成unsigned long 形式

	//4.获取指定函数的地址：
	HMODULE kernel32 = LoadLibraryA("kernel32.dll");
	FARPROC loadlibrary = GetProcAddress(kernel32, "LoadLibraryA"); //获得LoadLibraryA的地址。
	FARPROC getprocaddress = GetProcAddress(kernel32, "GetProcAddress"); //获得DLL的指定函数地址 
	FARPROC exitthread = GetProcAddress(kernel32, "ExitThread");
	FARPROC freelibraryandexitthread = GetProcAddress(kernel32,"FreeLibraryAndExitThread");

	//
	DWORD currentIdx = 0;
	DWORD dwTmp = 0;
	
	//填充三个指针空间
	size_t sizePtr = sizeof(int*);
	const size_t addressCount = 3;
	for (size_t i = 0; i < addressCount * sizePtr; i++)
	{
		currentAddress[i] = 0x00; //分配字节；（空字节）
	}
	currentIdx += addressCount * sizePtr;		// 相当于空出了12个字节

	//？？？？i dont know
	DWORD user32Addr = targetAddress + 0;		// 存放User32.dll的模块地址
	DWORD msgboxAddr = targetAddress + 4;		// 存放User32.dll中MessageBoxA的模块地址
	DWORD injectDllAddr = targetAddress + 8;	// 存放待注入的dll的加载地址

	//填充字符串


	return true;
}

//注入64位程序
bool InjectDll::inject64Process(DWORD dwPid, const char* dllName)
{
	return true;
}