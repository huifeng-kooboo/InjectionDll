#pragma once
#include<iostream>
#include<Windows.h>

class InjectDll
{
	//会自动声明构造函数和析构函数。
public :
	bool is64BitOS();
	bool is64BitProcess(DWORD dwPid);
	bool TestInjectDll(LPCWSTR wins_title,const char* dllName);
	bool inject32Process(DWORD dwPid,const char * dllName);
	bool inject64Process(DWORD dwPid, const char* dllName);

	//注入结果
	enum injectresult
	{
		INJECT_ERROR, //注入失败
		INJECT_OK   //注入成功
	};
};