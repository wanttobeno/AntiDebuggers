// tlssup.cÎÄ¼ş´úÂë£º
#include <windows.h>
#include <winnt.h>

int _tls_index=0;

#pragma data_seg(".tls")
int _tls_start=0;
#pragma data_seg(".tls$ZZZ")
int _tls_end=0;
#pragma data_seg(".CRT$XLA")
int __xl_a=0;
#pragma data_seg(".CRT$XLZ")
int __xl_z=0;

#pragma data_seg(".rdata$T")

extern PIMAGE_TLS_CALLBACK my_tls_callbacktbl[];

IMAGE_TLS_DIRECTORY32 _tls_used={(DWORD)&_tls_start,(DWORD)&_tls_end,(DWORD)&_tls_index,(DWORD)my_tls_callbacktbl,0,0};

