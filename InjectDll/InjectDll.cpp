// InjectDll.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include "InjectDll.h"

using namespace std;

int main()
{
	InjectDll* inject = new InjectDll();
	inject->TestInjectDll(L"TIM","demo.dll");

}


