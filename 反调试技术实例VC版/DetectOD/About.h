#if !defined(AFX_ABOUT_H__E6A0B5AD_AEAB_4C62_B057_2E9C36D008CF__INCLUDED_)
#define AFX_ABOUT_H__E6A0B5AD_AEAB_4C62_B057_2E9C36D008CF__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// About.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CAbout dialog

class CAbout : public CDialog
{
// Construction
public:
	CAbout(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CAbout)
	enum { IDD = IDD_DETECTOD_DIALOG };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAbout)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CAbout)
		// NOTE: the ClassWizard will add member functions here
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_ABOUT_H__E6A0B5AD_AEAB_4C62_B057_2E9C36D008CF__INCLUDED_)
