#pragma once
#include<iostream>
#include<Windows.h>

class InjectDll
{
	//���Զ��������캯��������������
public :
	bool is64BitOS();
	bool is64BitProcess(DWORD dwPid);
	bool TestInjectDll(LPCWSTR wins_title,const char* dllName);
	bool inject32Process(DWORD dwPid,const char * dllName);
	bool inject64Process(DWORD dwPid, const char* dllName);

	//ע����
	enum injectresult
	{
		INJECT_ERROR, //ע��ʧ��
		INJECT_OK   //ע��ɹ�
	};
};