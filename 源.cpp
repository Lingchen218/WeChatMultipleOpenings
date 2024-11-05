#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <atlstr.h>
#include <TlHelp32.h>
#include <vector>
#include <exception>


//#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2


using NTQUERYSYSTEMINFORMATION = NTSTATUS(*)(ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

typedef NTSTATUS(NTAPI* NTDUPLICATEOBJECT)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI* NTQUERYOBJECT)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;



/*
	brief：*获取进程PID
	parm1: 进程名称
	ret: 成功->进程PID
		 失败->-1 空的列表
*/
std::vector<int> getPidsByName( const wchar_t processName[MAX_PATH] )
{
	HANDLE hSnapshot;
	LPPROCESSENTRY32 lppe;
	PROCESSENTRY32W ssss;
	lppe = &ssss;
	BOOL Found;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	lppe->dwSize = sizeof(PROCESSENTRY32);
	//lppedwSize
	Found = Process32First(hSnapshot, lppe);
	//WCHAR mProce[MAX_PATH] = processName;
	int pid = -1;
	std::vector<int> getPids;
	while (Found)
	{
		//strcpy(mProce, processName);
		//strcat(mProce, ".exe");
		if (wcscmp(processName, lppe->szExeFile) == 0)//进程名比较  
		{
			Found = TRUE;
			pid = lppe->th32ProcessID;
			getPids.emplace_back(pid);
			//break;
		}
		
		Found = Process32Next(hSnapshot, lppe);//得到下一个进程  
	}
	CloseHandle(hSnapshot);
	return getPids;
}





int enumhandle(DWORD ProcessId, const wchar_t Mutant1[])
{
	

	
	static HMODULE hNtMod = LoadLibrary(L"ntdll.dll");
	if (!hNtMod)
	{
		return 0;
	}

	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hNtMod, "NtQuerySystemInformation");
	NTDUPLICATEOBJECT NtDuplicateObject = (NTDUPLICATEOBJECT)GetProcAddress(hNtMod, "NtDuplicateObject");
	NTQUERYOBJECT NtQueryObject = (NTQUERYOBJECT)GetProcAddress(hNtMod, "NtQueryObject");

	if (!NtQuerySystemInformation || !NtDuplicateObject || !NtQueryObject)
	{
		return 0;
	}

	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
	HANDLE processHandle;
	ULONG i;
	ULONG neededSize = 0x1000;
	NTSTATUS Status = 0;
	ULONG ReturnLength = 0;
	// NtQuerySystemInformation won't give us the correct buffer size,
	//  so we guess by doubling the buffer size.

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(neededSize);
	//DUPLICATE_CLOSE_SOURCE();
	
	if (!handleInfo)
	{
		return 0;
	}

	//一直查询 直到成功
	while (STATUS_INFO_LENGTH_MISMATCH == (Status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		neededSize,
		&ReturnLength
	)))
	{
		if (handleInfo)
		{
			free(handleInfo);
			handleInfo = NULL;
		}
		neededSize = ReturnLength;
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(neededSize);
		if (!handleInfo)
		{

			return 0;
		}
	}
	processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ProcessId);
	if (!processHandle)return 0;
	for (i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		//CloseHandle(handle);
		DUPLICATE_SAME_ACCESS;
		//GetCurrentProcess();
		if (handle.ProcessId != ProcessId)
		{
			continue;
		}
		
		

		if (processHandle)
		{
			HANDLE dupHandle = NULL;
			POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;
			PVOID objectNameInfo = NULL;
			UNICODE_STRING objectName = { 0 };
			ULONG returnLength = 0;

			
			do{
				//句柄复制失败 就不去获取类型名
				Status = NtDuplicateObject(
					processHandle,
					(void*)handle.Handle,
					GetCurrentProcess(),
					&dupHandle,
					0,
					0,
					0
				);
				if (!NT_SUCCESS(Status))
				{
					break;
				}

				//获取对象类型名
				ULONG ObjectInformationLength = 0;
				while (STATUS_INFO_LENGTH_MISMATCH == (Status = NtQueryObject(
					dupHandle,
					ObjectTypeInformation,
					objectTypeInfo,
					ObjectInformationLength,
					&returnLength
				)))
				{
					if (objectTypeInfo)
					{
						free(objectTypeInfo);
						objectTypeInfo = NULL;
					}

					ObjectInformationLength = returnLength;
					objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(ObjectInformationLength);
					if (!objectTypeInfo)
					{
						break;
					}
				}

				//获取对象类型名成功
				if (NT_SUCCESS(Status))
				{
					

				}

				// Query the object name (unless it has an access of
				// 0x0012019f, on which NtQueryObject could hang.
				if (handle.GrantedAccess == 0x0012019f) {

					break;
				}

				//获取对象名
				ObjectInformationLength = 0;
				returnLength = 0;

				if (STATUS_INFO_LENGTH_MISMATCH == NtQueryObject(
					dupHandle,
					ObjectNameInformation,
					NULL,
					0,
					&returnLength
				)) {

					objectNameInfo = (POBJECT_TYPE_INFORMATION)malloc(returnLength);
					if (!objectNameInfo)
					{
						break;
					}

					ZeroMemory(objectNameInfo, returnLength);
					Status = NtQueryObject(
						dupHandle,
						ObjectNameInformation,
						objectNameInfo,
						returnLength,
						NULL);

				}

				//获取对象名成功
				if (NT_SUCCESS(Status) && ((PUNICODE_STRING)objectNameInfo)->Length > 0)
				{
					UNICODE_STRING objectName = *(PUNICODE_STRING)objectNameInfo;
					
					//wprintf(L"ceshi %s\n",objectTypeInfo->Name.Buffer);
					 const wchar_t Mutant[] = L"Mutant";
					 // \Sessions\1\BaseNamedObjects\_WeChat_App_Instance_Identity_Mutex_Name
					 

					 // 先判断类型
					if (!wcscmp(objectTypeInfo->Name.Buffer, Mutant)) {
						//printf(" 对象类型名:%wZ\n", &objectTypeInfo->Name);
						
						if (!wcscmp(objectName.Buffer, Mutant1)) {
							printf(" 对象名:%wZ\n", &objectName);
							DuplicateHandle(processHandle, (HANDLE)(handle.Handle), NULL, NULL, 0, false, DUPLICATE_CLOSE_SOURCE);
							printf("句柄值%d\n", handle.Handle); // 数字
						}
						else {
							// std::cout << objectName.Buffer << std::endl;
							//wchar_t* p = L"hello world.";
							char descBuf[128] = { 0 };
							sprintf(descBuf, "%S", objectName.Buffer);
							printf("str: %s\n", descBuf);
							//sprintf_s(descBuf, 128,objectName.Buffer)
							//wsprintf(objectName.Buffer, "%S", descBuf);


						}
						
						
						
					}
					
				}

			} while (false);//;

			// 关闭句柄
			if (dupHandle)
			{
				CloseHandle(dupHandle);
				dupHandle = nullptr;
			}
			if (objectTypeInfo)
			{
				free(objectTypeInfo);
				objectTypeInfo = nullptr;
			}
			if (objectNameInfo)
			{
				free(objectNameInfo);
				objectNameInfo = nullptr;
			}

		}
	}

	free(handleInfo);
	return 0;
}

int weixinshuankaimain() {
	std::vector<int> pids = getPidsByName(L"WeChat.exe");
	if (pids.size() < 1) {
		std::cout << "未找到微信\n";
		return 0;
	}
	const wchar_t Mutant1[] = L"\\Sessions\\1\\BaseNamedObjects\\_WeChat_App_Instance_Identity_Mutex_Name";
	for (int& i : pids) {
		// 如果有多个微信，需要判断多个微信是不是都关闭了互斥体句柄
		enumhandle(i, Mutant1);
	}
	return 0;
}


int GetScreenRect(int a = 0)
{
#define ScrRectNum 10 // 显示器的最大数量
	RECT m_ScrRect[ScrRectNum];
	int count = 0;
	for (int ScreenNo = 0; true; ++ScreenNo)
	{
		BOOL flag;
		DISPLAY_DEVICE dd;
		ZeroMemory(&dd, sizeof(dd));
		dd.cb = sizeof(dd);

		//枚举显示器，获取后面要用的名字，注意这会返回系统所能支持的所有显示器，ScreenNo从0开始，直到返回FALSE
		flag = EnumDisplayDevices(NULL, ScreenNo, &dd, EDD_GET_DEVICE_INTERFACE_NAME);
		if (!flag)
		{
			break;
		}

		DEVMODE dm;
		ZeroMemory(&dm, sizeof(dm));
		dm.dmSize = sizeof(dm);
		//返回当前设置，如果失败表明显示器不在线
		flag = EnumDisplaySettingsEx(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm, 0);
		if (!flag)
		{
			continue;
		}

		m_ScrRect[count].left = dm.dmPosition.x;//如果副显示器在左边，则这个值是负的
		m_ScrRect[count].top = dm.dmPosition.y;
		m_ScrRect[count].right = m_ScrRect[count].left + dm.dmPelsWidth - 1;
		m_ScrRect[count].bottom = m_ScrRect[count].top + dm.dmPelsHeight - 1;
		++count;
		std::cout << dd.DeviceName << " (dmBitsPerPel " << dm.dmBitsPerPel << " dmLogPixels" << dm.dmLogPixels << ") "
			<< dm.dmPosition.x << " " << dm.dmPosition.y << " " << dm.dmPelsWidth << " " << dm.dmPelsHeight << std::endl;
	}
	std::cout << "检索到显示器 " << count << std::endl;
	return count;
}

void wcharTochar(const wchar_t* wchar, char* chr, int length)
{
	WideCharToMultiByte(CP_ACP, 0, wchar, -1,
		chr, length, NULL, NULL);
}

int main(int argc, WCHAR* argv[]) {
	
	//int b = 0x123;
	//MessageBoxA(0,0,0,0);
	
	//std::cout << "显示器数量"<< GetScreenRect()<<std::endl;
	/*size_t bs = wcslen(argv[1]) * 2;
	char* buffer = (char*)malloc(bs);

	char descBuf[128] = { 0 };
	sprintf(descBuf, "%S", argv[1]);
	printf("str: %s\n", descBuf);*/
	// char descBuf[128] = { 0 };
	//sprintf(descBuf, "%S", argv[1]);
	

	// wcharTochar(argv[1], descBuf, sizeof(descBuf));
	 // printf("str: %s\n", descBuf);
	//printf("%S\n", argv[0]);
	// std::cout << argc << std::endl;
	 // std::cout << argv[1] << std::endl;
	weixinshuankaimain();
	/*try {
		CloseHandle((HANDLE)0xf4);
	}
	catch (std::exception & e) {
		 printf("检测到调试");
	}*/
	
	return 0;
}

