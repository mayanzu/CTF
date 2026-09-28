#include <windows.h>
__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) { (void)module; (void)reason; (void)reserved; return TRUE; }
__declspec(dllexport) void exit(int code) { ExitProcess((UINT)code); }
