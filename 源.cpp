#include "win.h"
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




/*
	brief��*��ȡ����PID
	parm1: ��������
	ret: �ɹ�->����PID
		 ʧ��->-1 �յ��б�
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
		if (wcscmp(processName, lppe->szExeFile) == 0)//�������Ƚ�  
		{
			Found = TRUE;
			pid = lppe->th32ProcessID;
			getPids.emplace_back(pid);
			//break;
		}
		
		Found = Process32Next(hSnapshot, lppe);//�õ���һ������  
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
		// �����ڴ�ʧ��
		return 0;
	}

	//һֱ��ѯ ֱ���ɹ�
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
				//�������ʧ�� �Ͳ�ȥ��ȡ������
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

				//��ȡ����������
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

				//��ȡ�����������ɹ�
				if (NT_SUCCESS(Status))
				{
					

				}

				// Query the object name (unless it has an access of
				// 0x0012019f, on which NtQueryObject could hang.
				if (handle.GrantedAccess == 0x0012019f) {

					break;
				}

				//��ȡ������
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

				//��ȡ�������ɹ�
				if (NT_SUCCESS(Status) && ((PUNICODE_STRING)objectNameInfo)->Length > 0)
				{
					UNICODE_STRING objectName = *(PUNICODE_STRING)objectNameInfo;
					
					//wprintf(L"ceshi %s\n",objectTypeInfo->Name.Buffer);
					 const wchar_t Mutant[] = L"Mutant";
					 // \Sessions\1\BaseNamedObjects\_WeChat_App_Instance_Identity_Mutex_Name
					 

					 // ���ж�����
					if (!wcscmp(objectTypeInfo->Name.Buffer, Mutant)) {
						//printf(" ����������:%wZ\n", &objectTypeInfo->Name);
						
						if (!wcscmp(objectName.Buffer, Mutant1)) {
							printf(" ������:%wZ\n", &objectName);
							DuplicateHandle(processHandle, (HANDLE)(handle.Handle), NULL, NULL, 0, false, DUPLICATE_CLOSE_SOURCE);
							printf("���ֵ%d\n", handle.Handle); // ����
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

			// �رվ��
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
	
	std::vector<int> pids = getPidsByName(_T("WeChat.exe"));
	if (pids.size() < 1) {
		std::cout << "WeChat.exe\n";
		return 0;
	}
	const wchar_t Mutant1[] = L"\\Sessions\\1\\BaseNamedObjects\\_WeChat_App_Instance_Identity_Mutex_Name";
	for (int& i : pids) {
		// ����ж��΢�ţ���Ҫ�ж϶��΢���ǲ��Ƕ��ر��˻�������
		enumhandle(i, Mutant1);
	}
	return 0;
}


int GetScreenRect(int a = 0)
{
#define ScrRectNum 10 // ��ʾ�����������
	RECT m_ScrRect[ScrRectNum];
	int count = 0;
	for (int ScreenNo = 0; true; ++ScreenNo)
	{
		BOOL flag;
		DISPLAY_DEVICE dd;
		ZeroMemory(&dd, sizeof(dd));
		dd.cb = sizeof(dd);

		//ö����ʾ������ȡ����Ҫ�õ����֣�ע����᷵��ϵͳ����֧�ֵ�������ʾ����ScreenNo��0��ʼ��ֱ������FALSE
		flag = EnumDisplayDevices(NULL, ScreenNo, &dd, EDD_GET_DEVICE_INTERFACE_NAME);
		if (!flag)
		{
			break;
		}

		DEVMODE dm;
		ZeroMemory(&dm, sizeof(dm));
		dm.dmSize = sizeof(dm);
		//���ص�ǰ���ã����ʧ�ܱ�����ʾ��������
		flag = EnumDisplaySettingsEx(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm, 0);
		if (!flag)
		{
			continue;
		}

		m_ScrRect[count].left = dm.dmPosition.x;//�������ʾ������ߣ������ֵ�Ǹ���
		m_ScrRect[count].top = dm.dmPosition.y;
		m_ScrRect[count].right = m_ScrRect[count].left + dm.dmPelsWidth - 1;
		m_ScrRect[count].bottom = m_ScrRect[count].top + dm.dmPelsHeight - 1;
		++count;
		std::cout << dd.DeviceName << " (dmBitsPerPel " << dm.dmBitsPerPel << " dmLogPixels" << dm.dmLogPixels << ") "
			<< dm.dmPosition.x << " " << dm.dmPosition.y << " " << dm.dmPelsWidth << " " << dm.dmPelsHeight << std::endl;
	}
	std::cout << "��������ʾ�� " << count << std::endl;
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
	
	//std::cout << "��ʾ������"<< GetScreenRect()<<std::endl;
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
		 printf("��⵽����");
	}*/
	
	return 0;
}

