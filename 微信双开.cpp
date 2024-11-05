// 微信双开.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <atlbase.h>
// #include <atlstr.h>
int  wcscasecmp(const  wchar_t* cs, const  wchar_t* ct)
{
    while (towlower(*cs) == towlower(*ct))
    {
        if (*cs == 0)
            return 0;
        cs++;
        ct++;
    }
    return towlower(*cs) - towlower(*ct);
}




HANDLE GetProcessHandle(int nID)
{
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, nID);
}

//通过进程名（带后缀.exe）获取进程句柄
HANDLE GetProcessHandle(LPCWSTR lpName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return NULL;
    }
    PROCESSENTRY32 pe = { sizeof(pe) };
    BOOL fOk;
    MessageBoxA(0, "fdddd", 0, 0);
    for (fOk = Process32First(hSnapshot, &pe); fOk; fOk = Process32Next(hSnapshot, &pe))
    {
        if (!wcscasecmp(pe.szExeFile, lpName)) // 不区分大小写
        {
            CloseHandle(hSnapshot);
            return GetProcessHandle(pe.th32ProcessID);
        }
    }
    return NULL;

}

void test() {

    // 获取进程句柄
    //const char  sd[] = "wechat.exe";
    LPCWSTR aaav = _T("wechat.exe");
    GetProcessHandle(aaav);

    char s[] = "\\Sessions\\1\\BaseNamedObjects\\_WeChat_App_Instance_ldentity_Mutex_Name";
    WCHAR wszClassName[256];
    memset(wszClassName, 0, sizeof(wszClassName));
    MultiByteToWideChar(CP_ACP, 0, s, strlen(s) + 1, wszClassName,
        sizeof(wszClassName) / sizeof(wszClassName[0]));
    _T("\\Sessions\\1\\BaseNamedObjects\\_WeChat_App_Instance_ldentity_Mutex_Name");
    HANDLE hProcess = OpenMutex(MUTEX_ALL_ACCESS, true, _T("\\Sessions\\1\\BaseNamedObjects\\_WeChat_App_Instance_ldentity_Mutex_Name"));
    if (hProcess == NULL) {
        std::cout << "OpenProcess failed: " << GetLastError() << std::endl;
        return;
    }
    //\Sessions\1\BaseNamedObjects\_WeChat_App_Instance_ldentity_Mutex_Name
    
    // 关闭指定句柄
    HANDLE hHandle = (HANDLE)0x12345678;
    if (!CloseHandle(hHandle)) {
        std::cout << "CloseHandle failed: " << GetLastError() << std::endl;
    }

    // 关闭进程句柄
    if (!CloseHandle(hProcess)) {
        std::cout << "CloseHandle failed: " << GetLastError() << std::endl;
    }
}



int main22() {
    auto bb = typeid(0.716 * 159430).raw_name();
    std::cout << bb << std::endl;
    std::cout << 0.716*159430 << std::endl;
    //uint8 b;
    bool ccc = typeid(0.716 * 159430).before(typeid(0.716 * 159430));
    unsigned int a;
    unsigned long long b;
    std::cout << ccc;
    //test();

    return 0;
}


// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
