#include "InjectDll.h"
using namespace std;

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


	return true;
}

//ע��64λ����
bool InjectDll::inject64Process(DWORD dwPid, const char* dllName)
{
	return true;
}