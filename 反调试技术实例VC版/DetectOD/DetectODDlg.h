// DetectODDlg.h : header file
//

#if !defined(AFX_DETECTODDLG_H__878B65B9_998E_4718_93F3_D147DB13A90D__INCLUDED_)
#define AFX_DETECTODDLG_H__878B65B9_998E_4718_93F3_D147DB13A90D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/////////////////////////////////////////////////////////////////////////////
// CDetectODDlg dialog

class CDetectODDlg : public CDialog
{
// Construction
public:
	CDetectODDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CDetectODDlg)
	enum { IDD = IDD_DETECTOD_DIALOG };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CDetectODDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CDetectODDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnWndcls();
	afx_msg void OnTest();
	afx_msg void OnIsdebuggerpresent();
	afx_msg void OnEnumwindow();
	afx_msg void OnEnumProcess();
	afx_msg void OnExplorer();
	afx_msg void OnGetTickCount();
	afx_msg void OnGetStartupInfo();
	afx_msg void OnPebflags();
	afx_msg void OnCheckremotedebuggerpresent();
	afx_msg void OnZwqueryinfomationprocess();
	afx_msg void OnSetUnhandledExceptionFilter();
	afx_msg void OnZwQueryInformationProcess();
	afx_msg void OnSeDebugPrivilege();
	afx_msg void OnNTQueryObject();
	afx_msg void OnDectectBreakpoints();
	afx_msg void OnDectectFuncBreakpoints();
	afx_msg void OnBlockInput();
	afx_msg void OnChecksum();
	afx_msg void OnEnableWindow();
	afx_msg void OnZwSetInformationThread();
	afx_msg void OnOutputDebugString();
	afx_msg void OnGetEntryPoint();
	afx_msg void OnButton1();
	afx_msg void OnButton2();
	afx_msg void OnTrapFlag();
	afx_msg void OnGuardPages();
	afx_msg void OnHardwarebreakpoint();
	virtual void OnCancel();
	afx_msg void OnAbout();
	virtual void OnOK();
	afx_msg void OnMypage2();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_DETECTODDLG_H__878B65B9_998E_4718_93F3_D147DB13A90D__INCLUDED_)
