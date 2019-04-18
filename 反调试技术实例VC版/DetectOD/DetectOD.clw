; CLW file contains information for the MFC ClassWizard

[General Info]
Version=1
LastClass=CAboutDlg
LastTemplate=CDialog
NewFileInclude1=#include "stdafx.h"
NewFileInclude2=#include "DetectOD.h"

ClassCount=4
Class1=CDetectODApp
Class2=CDetectODDlg
Class3=CAboutDlg

ResourceCount=3
Resource1=IDR_MAINFRAME
Resource2=IDD_ABOUTBOX
Class4=CAbout
Resource3=IDD_DETECTOD_DIALOG

[CLS:CDetectODApp]
Type=0
HeaderFile=DetectOD.h
ImplementationFile=DetectOD.cpp
Filter=N

[CLS:CDetectODDlg]
Type=0
HeaderFile=DetectODDlg.h
ImplementationFile=DetectODDlg.cpp
Filter=D
BaseClass=CDialog
VirtualFilter=dWC
LastObject=CDetectODDlg

[CLS:CAboutDlg]
Type=0
HeaderFile=DetectODDlg.h
ImplementationFile=DetectODDlg.cpp
Filter=D
BaseClass=CDialog
VirtualFilter=dWC
LastObject=CAboutDlg

[DLG:IDD_ABOUTBOX]
Type=1
Class=CAboutDlg
ControlCount=4
Control1=IDC_MYICON,static,1342177539
Control2=IDC_COMEON,static,1342177536
Control3=IDOK,button,1342373889
Control4=IDC_MYPAGE,static,1342308609

[DLG:IDD_DETECTOD_DIALOG]
Type=1
Class=CAbout
ControlCount=27
Control1=IDOK,button,1342242817
Control2=IDC_WNDCLS,button,1342242816
Control3=IDC_ISDEBUGGERPRESENT,button,1342242816
Control4=IDC_ENUMWINDOW,button,1342242816
Control5=IDC_EnumProcess,button,1342242816
Control6=IDC_Explorer,button,1342242816
Control7=IDC_GetTickCount,button,1342242816
Control8=IDC_GetStartupInfo,button,1342242816
Control9=IDC_PEBFLAGS,button,1342242816
Control10=IDC_CHECKREMOTEDEBUGGERPRESENT,button,1342242816
Control11=IDC_ZwQueryInformationProcess,button,1342242816
Control12=IDC_SetUnhandledExceptionFilter,button,1342242816
Control13=IDC_SeDebugPrivilege,button,1342242816
Control14=IDC_NTQueryObject,button,1342242816
Control15=IDC_DectectBreakpoints,button,1342242816
Control16=IDC_DectectFuncBreakpoints,button,1342242816
Control17=IDC_BlockInput,button,1342242816
Control18=IDC_CHECKSUM,button,1342242816
Control19=IDC_EnableWindow,button,1342242816
Control20=IDC_ZwSetInformationThread,button,1342242816
Control21=IDC_OutputDebugString,button,1342242816
Control22=IDC_GetEntryPoint,button,1342242816
Control23=IDC_TrapFlag,button,1342242816
Control24=IDC_GuardPages,button,1342242816
Control25=IDC_HARDWAREBREAKPOINT,button,1342242816
Control26=IDC_ABOUT,button,1342242816
Control27=IDC_MYPAGE2,static,1342308609

[CLS:CAbout]
Type=0
HeaderFile=About.h
ImplementationFile=About.cpp
BaseClass=CDialog
Filter=D
LastObject=CAbout

