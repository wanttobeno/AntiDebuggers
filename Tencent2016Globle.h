#pragma once

#include <windows.h>

typedef DWORD (WINAPI *NtQueryInformationProcessPtr)(
       HANDLE processHandle,
       DWORD processInformationClass,
       PVOID processInformation,
       ULONG processInformationLength,
       PULONG returnLength);

typedef enum enumSYSTEM_INFORMATION_CLASS  
{  
    SystemBasicInformation,  
    SystemProcessorInformation,  
    SystemPerformanceInformation,  
    SystemTimeOfDayInformation,  
}SYSTEM_INFORMATION_CLASS;  
   
typedef struct tagPROCESS_BASIC_INFORMATION  
{  
    DWORD ExitStatus;  
    DWORD PebBaseAddress;  
    DWORD AffinityMask;  
    DWORD BasePriority;  
    ULONG UniqueProcessId;  
    ULONG InheritedFromUniqueProcessId;  
}PROCESS_BASIC_INFORMATION;  
  
typedef LONG (WINAPI *PNTQUERYINFORMATIONPROCESS)(HANDLE,UINT,PVOID,ULONG,PULONG);