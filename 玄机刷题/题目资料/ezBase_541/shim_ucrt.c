#include <windows.h>
#include <stdlib.h>
__declspec(dllexport) void exit(int code) { ExitProcess((UINT)code); }
