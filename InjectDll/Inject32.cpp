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
	//0x00�������
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
	0xA3, 0x00, 0x00, 0x00, 0x00,		// 77	MOV [injectDllAddr], EAX	:����mutehook.dll�ĵ�ַ
	0x68, 0x00, 0x00, 0x00, 0x00,		// 82	PUSH {injectFuncNameAddr}	:inject.dll�ĵ�������
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
	0x68, 0x00, 0x00, 0x00, 0x00,		// 128	PUSH [injectParamAddr]		:���������Ĳ���
	0xFF, 0xD0,							// 133	CALL EAX					:Call ExitThread���ߵ�������
};

//�ж��Ƿ�Ϊ64λϵͳ
bool InjectDll::is64BitOS()
{
	SYSTEM_INFO cur_system_info;
	GetNativeSystemInfo(&cur_system_info);
	WORD system_str = cur_system_info.wProcessorArchitecture;
	//�ж��Ƿ�Ϊ64λϵͳ
	if (system_str == PROCESSOR_ARCHITECTURE_IA64 || system_str == PROCESSOR_ARCHITECTURE_AMD64)
	{
		return true;
	}
	return false;
}

//�ж��Ƿ�Ϊ64λ����
//@param:����id
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
//Params: �������,dll����
bool InjectDll::TestInjectDll(LPCWSTR wins_title, const char* dllName)
{
	HWND hWnd = FindWindow(NULL, wins_title); //��øó���ľ��
	if (hWnd == nullptr)
	{
		cout << "��ǰ���򲻴���" << endl;
		return false;
	}
	DWORD dwPid;
	DWORD dwThreadId = GetWindowThreadProcessId(hWnd, &dwPid); //dwThreadId:��ǰ������߳�ID��dwPid:��ǰ����Ľ���Pid
	bool flag_process = is64BitProcess(dwPid); //�ж��Ƿ�Ϊ64λ����
	if (flag_process)//64λ����ʱ
	{
		inject64Process(dwPid, dllName);
	}
	else //32λ����ʱ
	{
		inject32Process(dwPid, dllName);
	}
	return true;
}

//ע��32λ����
bool InjectDll::inject32Process(DWORD dwPid, const char* dllName)
{
	//1.�򿪶�Ӧ���̣���ȡ�ý��̵ľ��
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |  
		PROCESS_CREATE_THREAD |   
		PROCESS_VM_OPERATION |  
		PROCESS_VM_WRITE,         
		FALSE, dwPid);//�򿪶�Ӧ����
	if (hProcess == NULL)
	{
		return INJECT_ERROR;
	}

	//2.�����ڴ棬�öѷ���
	LPBYTE currentAddress = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);
	if (NULL == currentAddress)
	{
		return INJECT_ERROR;
	}

	//3.��ָ��������ռ䱣���ڴ�
	LPVOID targetWorkspace = VirtualAllocEx(hProcess, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //�ڽ��̵�����ռ䱣�����ύ�ڴ����򣬷���ֵΪ��������ĵ�ַ
		//�жϷ����Ƿ�ɹ�
	if (NULL == targetWorkspace)
	{
		return INJECT_ERROR;
	}

	DWORD targetAddress = PtrToUlong(targetWorkspace); //��ַת��unsigned long ��ʽ

	//4.��ȡָ�������ĵ�ַ��
	HMODULE kernel32 = LoadLibraryA("kernel32.dll");
	FARPROC loadlibrary = GetProcAddress(kernel32, "LoadLibraryA"); //���LoadLibraryA�ĵ�ַ��
	FARPROC getprocaddress = GetProcAddress(kernel32, "GetProcAddress"); //���DLL��ָ��������ַ 
	FARPROC exitthread = GetProcAddress(kernel32, "ExitThread");
	FARPROC freelibraryandexitthread = GetProcAddress(kernel32,"FreeLibraryAndExitThread");

	//
	DWORD currentIdx = 0;
	DWORD dwTmp = 0;
	
	//�������ָ��ռ�
	size_t sizePtr = sizeof(int*);
	const size_t addressCount = 3;
	for (size_t i = 0; i < addressCount * sizePtr; i++)
	{
		currentAddress[i] = 0x00; //�����ֽڣ������ֽڣ�
	}
	currentIdx += addressCount * sizePtr;		// �൱�ڿճ���12���ֽ�

	//��������i dont know
	DWORD user32Addr = targetAddress + 0;		// ���User32.dll��ģ���ַ
	DWORD msgboxAddr = targetAddress + 4;		// ���User32.dll��MessageBoxA��ģ���ַ
	DWORD injectDllAddr = targetAddress + 8;	// ��Ŵ�ע���dll�ļ��ص�ַ

	//����ַ���
	char user32Name[MAX_PATH + 1] = { 0 };
	char msgboxName[MAX_PATH + 1] = { 0 };
	char injectDllName[MAX_PATH + 1] = { 0 };
	char injectFuncName[MAX_PATH + 1] = { 0 };
	char injectParam[MAX_PATH * 2 + 1] = { 0 };
	char injectErrorTitle[MAX_PATH + 1] = { 0 };
	char injectErrorMsg1[MAX_PATH + 1] = { 0 };
	char injectErrorMsg2[MAX_PATH + 1] = { 0 };
	//_snprintf_s(injectDllName, MAX_PATH, MAX_PATH - 1, "%s", dllname);//��ʽ���ַ���
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
	FillInString(user32NameAddr, user32Name) //����ַ���
	FillInString(msgboxNameAddr, msgboxName)
	FillInString(injectDllNameAddr, injectDllName)
	FillInString(injectFuncNameAddr, injectFuncName)
	FillInString(injectParamAddr, injectParam)
	FillInString(injectErrorTitleAddr, injectErrorTitle)
	FillInString(injectErrorMsg1Addr, injectErrorMsg1)
	FillInString(injectErrorMsg2Addr, injectErrorMsg2)

	// 4.4. ���һЩint3���ָ��ַ������ʹ�����
	const size_t int3_count = 3;
	for (size_t i = 0; i < int3_count; i++)
	{
		currentAddress[currentIdx++] = 0xCC;
	}

	// 4.5 ���������Ĵ��뿪ʼλ��
	DWORD targetExcuteCodeAddress = targetAddress + currentIdx;

	// 4.6. ����������
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
		VirtualProtectEx(hProcess, targetWorkspace, currentIdx, PAGE_EXECUTE_READWRITE, &oldProtect); //���ÿ��Խ��ж�д

		// Step6. Write out the patch
		DWORD bytesRet = 0;
		if (!WriteProcessMemory(hProcess, targetWorkspace, currentAddress, currentIdx, &bytesRet))
		{
			return INJECT_ERROR;
		}

		// Step7. Restore page protection
		VirtualProtectEx(hProcess, targetWorkspace, currentIdx, oldProtect, &oldProtect);

		// Step8. Make sure our changes are written right away
		FlushInstructionCache(hProcess, targetWorkspace, currentIdx); //ˢ��ָ������ָ����ٻ��棬��CPU�����µ�ָ��

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

//ע��64λ����
bool InjectDll::inject64Process(DWORD dwPid, const char* dllName)
{
	return true;
}