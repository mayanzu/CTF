#include <windows.h>
__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) { (void)module; (void)reason; (void)reserved; return TRUE; }
__declspec(dllexport) void *__current_exception(void) { return (void *)0; }
