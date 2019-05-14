#include "InjectDll.h"
using namespace std;

#define FillInString(addr, str)	\
	addr =  targetAddress + currentIdx;	\
	dwTmp = (DWORD)strlen(str) + 1;	\
	memcpy(currentAddress + currentIdx, str, dwTmp);	\
	currentIdx += dwTmp;

unsigned char injectCode_Tail_ExitThread[] = {
	0x6A, 0x00,								// 0	PUSH 0						
	0xB8, 0x00, 0x00, 0x00, 0x00,			// 2	MOV EAX, [exitthread]
	0xFF, 0xD0,								// 12	CALL EAX				:Call ExitThread
};


unsigned char injectCode_Head_NoSilent[] = {
	//0x00用于填充
	0x68, 0x00, 0x00, 0x00, 0x00,		// 0	PUSH {user32NameAddr}		:"user32.dll"
	0xB8, 0x00, 0x00, 0x00, 0x00,		// 5	MOV EAX, {FARPROC_LoadLibraryA}
	0xFF, 0xD0,							// 10	CALL EAX					:Call LoadLibraryA
	0x68, 0x00, 0x00, 0x00, 0x00,		// 12	PUSH {msgboxNameAddr}		:"MessageBoxA"
	0x50,								// 17	Push EAX
	0xB8, 0x00, 0x00, 0x00, 0x00,		// 18	MOV EAX, {FARPROC_GetProcAddress}
	0xFF, 0xD0,							// 23	CALL EAX					:Call GetProcAddress
	0xA3, 0x00, 0x00, 0x00, 0x00,		// 25	MOV [msgboxAddr], EAX
	0x68, 0x00, 0x00, 0x00, 0x00,		// 30	PUSH {injectDllNameAddr}	:"inject.dll"
	0xB8, 0x00, 0x00, 0x00, 0x00,		// 35	MOV EAX, {FARPROC_LoadLibraryA}
	0xFF, 0xD0,							// 40	CALL EAX					:Call LoadLibraryA
	0x83, 0xF8,	0x00,					// 42	CMP EAX, 0
	0x75, 0x1E,							// 45	JNZ EIP + 0x1E : skip over nRetor code
	0x6A, 0x10,							// 47	PUSH 0x10					:MB_ICONHAND
	0x68, 0x00, 0x00, 0x00, 0x00,		// 49	PUSH {injectErrorTitleAddr}	:MessageBox title
	0x68, 0x00, 0x00, 0x00, 0x00,		// 54	PUSH {injectErrorMsg1Addr}	:MessageBox message
	0x6A, 0x00,							// 59	PUSH 0						:HWND
	0xA1, 0x00, 0x00, 0x00, 0x00,		// 61	MOV EAX, [msgboxAddr]
	0xFF, 0xD0,							// 66	CALL EAX					:Call MessageBoxA
	0x6A, 0x00,							// 68	PUSH 0						
	0xB8, 0x00, 0x00, 0x00, 0x00,		// 70	MOV EAX, [exitthread]
	0xFF, 0xD0,							// 75	CALL EAX					:Call ExitThread
	0xA3, 0x00, 0x00, 0x00, 0x00,		// 77	MOV [injectDllAddr], EAX	:保存mutehook.dll的地址
	0x68, 0x00, 0x00, 0x00, 0x00,		// 82	PUSH {injectFuncNameAddr}	:inject.dll的导出函数
	0x50,								// 87	Push EAX					:
	0xB8, 0x00, 0x00, 0x00, 0x00,		// 88	MOV EAX, {FARPROC_GetProcAddress}
	0xFF, 0xD0,							// 93	CALL EAX					:Call GetProcAddress
	0x83, 0xF8,	0x00,					// 95	CMP EAX, 0
	0x75, 0x1C,							// 98	JNZ EIP + 0x1C : skip over nRetor code
	0x6A, 0x10,							// 100	PUSH 0x10					:MB_ICONHAND
	0x68, 0x00, 0x00, 0x00, 0x00,		// 102	PUSH {injectErrorTitleAddr}	:MessageBox title
	0x68, 0x00, 0x00, 0x00, 0x00,		// 107	PUSH {injectErrorMsg2Addr}	:MessageBox message
	0x6A, 0x00,							// 112	PUSH 0						:HWND
	0xA1, 0x00, 0x00, 0x00, 0x00,		// 114	MOV EAX, [msgboxAddr]
	0xFF, 0xD0,							// 119	CALL EAX					:Call MessageBoxA
	0x6A, 0x00,							// 121	PUSH 0						
	0xB8, 0x00, 0x00, 0x00, 0x00,		// 123	MOV EAX, [exitthread]
	0x68, 0x00, 0x00, 0x00, 0x00,		// 128	PUSH [injectParamAddr]		:导出函数的参数
	0xFF, 0xD0,							// 133	CALL EAX					:Call ExitThread或者导出函数
};

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
	char user32Name[MAX_PATH + 1] = { 0 };
	char msgboxName[MAX_PATH + 1] = { 0 };
	char injectDllName[MAX_PATH + 1] = { 0 };
	char injectFuncName[MAX_PATH + 1] = { 0 };
	char injectParam[MAX_PATH * 2 + 1] = { 0 };
	char injectErrorTitle[MAX_PATH + 1] = { 0 };
	char injectErrorMsg1[MAX_PATH + 1] = { 0 };
	char injectErrorMsg2[MAX_PATH + 1] = { 0 };
	//_snprintf_s(injectDllName, MAX_PATH, MAX_PATH - 1, "%s", dllname);//格式化字符串
	//_snprintf_s(injectFuncName, MAX_PATH, MAX_PATH - 1, "%s", funcname);
	//_snprintf_s(injectParam, MAX_PATH * 2, MAX_PATH * 2 - 1, "%s", param);
	_snprintf_s(user32Name, MAX_PATH, MAX_PATH - 1, "user32.dll");
	_snprintf_s(msgboxName, MAX_PATH, MAX_PATH - 1, "MessageBoxA");
	_snprintf_s(injectErrorTitle, MAX_PATH, MAX_PATH - 1, "Error");
	_snprintf_s(injectErrorMsg1, MAX_PATH, MAX_PATH - 1, "Could not load the dll: %s", injectDllName);
	_snprintf_s(injectErrorMsg2, MAX_PATH, MAX_PATH - 1, "Could not load the function: %s", injectFuncName);

	DWORD user32NameAddr = 0;
	DWORD msgboxNameAddr = 0;
	DWORD injectDllNameAddr = 0;
	DWORD injectFuncNameAddr = 0;
	DWORD injectParamAddr = 0;
	DWORD injectErrorTitleAddr = 0;
	DWORD injectErrorMsg1Addr = 0;
	DWORD injectErrorMsg2Addr = 0;
	FillInString(user32NameAddr, user32Name) //填充字符串
	FillInString(msgboxNameAddr, msgboxName)
	FillInString(injectDllNameAddr, injectDllName)
	FillInString(injectFuncNameAddr, injectFuncName)
	FillInString(injectParamAddr, injectParam)
	FillInString(injectErrorTitleAddr, injectErrorTitle)
	FillInString(injectErrorMsg1Addr, injectErrorMsg1)
	FillInString(injectErrorMsg2Addr, injectErrorMsg2)

	// 4.4. 填充一些int3来分隔字符串区和代码区
	const size_t int3_count = 3;
	for (size_t i = 0; i < int3_count; i++)
	{
		currentAddress[currentIdx++] = 0xCC;
	}

	// 4.5 保存真正的代码开始位置
	DWORD targetExcuteCodeAddress = targetAddress + currentIdx;

	// 4.6. 修正代码区
	memcpy(injectCode_Head_NoSilent + 1, &user32NameAddr, 4);
	memcpy(injectCode_Head_NoSilent + 6, &loadlibrary, 4);
	memcpy(injectCode_Head_NoSilent + 13, &msgboxNameAddr, 4);
	memcpy(injectCode_Head_NoSilent + 19, &getprocaddress, 4);
	memcpy(injectCode_Head_NoSilent + 26, &msgboxAddr, 4);
	memcpy(injectCode_Head_NoSilent + 31, &injectDllNameAddr, 4);
	memcpy(injectCode_Head_NoSilent + 36, &loadlibrary, 4);
	memcpy(injectCode_Head_NoSilent + 50, &injectErrorTitleAddr, 4);
	memcpy(injectCode_Head_NoSilent + 55, &injectErrorMsg1Addr, 4);
	memcpy(injectCode_Head_NoSilent + 62, &msgboxAddr, 4);
	memcpy(injectCode_Head_NoSilent + 71, &exitthread, 4);
	memcpy(injectCode_Head_NoSilent + 78, &injectDllAddr, 4);
	memcpy(injectCode_Head_NoSilent + 83, &injectFuncNameAddr, 4);
	memcpy(injectCode_Head_NoSilent + 89, &getprocaddress, 4);
	memcpy(injectCode_Head_NoSilent + 103, &injectErrorTitleAddr, 4);
	memcpy(injectCode_Head_NoSilent + 108, &injectErrorMsg2Addr, 4);
	memcpy(injectCode_Head_NoSilent + 115, &msgboxAddr, 4);
	memcpy(injectCode_Head_NoSilent + 124, &exitthread, 4);
	memcpy(injectCode_Head_NoSilent + 129, &injectParamAddr, 4);
	memcpy(currentAddress + currentIdx, injectCode_Head_NoSilent, sizeof(injectCode_Head_NoSilent));
	currentIdx += sizeof(injectCode_Head_NoSilent);

	memcpy(injectCode_Tail_ExitThread + 3, &exitthread, 4);
	memcpy(currentAddress + currentIdx, injectCode_Tail_ExitThread, sizeof(injectCode_Tail_ExitThread));
	currentIdx += sizeof(injectCode_Tail_ExitThread);

		// Step5. Change page protection so we can write executable code
		DWORD oldProtect = 0;
		VirtualProtectEx(hProcess, targetWorkspace, currentIdx, PAGE_EXECUTE_READWRITE, &oldProtect); //设置可以进行读写

		// Step6. Write out the patch
		DWORD bytesRet = 0;
		if (!WriteProcessMemory(hProcess, targetWorkspace, currentAddress, currentIdx, &bytesRet))
		{
			return INJECT_ERROR;
		}

		// Step7. Restore page protection
		VirtualProtectEx(hProcess, targetWorkspace, currentIdx, oldProtect, &oldProtect);

		// Step8. Make sure our changes are written right away
		FlushInstructionCache(hProcess, targetWorkspace, currentIdx); //刷新指定进程指令高速缓存，让CPU加载新的指令

		// Step9. Execute the thread now and wait for it to exit, note we execute where the code starts, and not the codecave start
		// (since we wrote strings at the start of the codecave) -- NOTE: void* used for VC6 compatibility instead of UlongToPtr
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((void*)targetExcuteCodeAddress), 0, 0, NULL);
		if (NULL == hThread)
		{
			return INJECT_ERROR;
		}
		WaitForSingleObject(hThread, INFINITE);

	// Step10. Cleanup
	if (hProcess)
	{
		CloseHandle(hProcess);
	}

	if (hThread)
	{
		CloseHandle(hThread);
	}

	// Free the memory in the process that we allocated
	if (targetWorkspace)
	{
		VirtualFreeEx(hProcess, targetWorkspace, 0, MEM_RELEASE);
	}

	// Free the currentAddress memory
	if (currentAddress)
	{
		HeapFree(GetProcessHeap(), 0, currentAddress);
	}
	return true;
}

//注入64位程序
bool InjectDll::inject64Process(DWORD dwPid, const char* dllName)
{
	return true;
}