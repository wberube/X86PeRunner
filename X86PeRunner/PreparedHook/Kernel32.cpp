#include"Kernel32.h"
#include<string.h>
#include<stdlib.h>

#define UNICORN_HOOK_FUNC(func) void PreparedHook::##func##(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)

using namespace PreparedHook;

// Global callbacks - set during initialization
static EXEC_MAIN_CALLBACK g_ExecMainCallback = NULL;
static IMPORT_CALLBACK g_ImportCallback = NULL;

// Initialize hook callbacks
void PreparedHook::InitializeHookCallbacks(EXEC_MAIN_CALLBACK execCallback, IMPORT_CALLBACK importCallback)
{
	g_ExecMainCallback = execCallback;
	g_ImportCallback = importCallback;
}

// Helper function to read strings from emulator memory
static void ReadStringFromEmulator(uc_engine *uc, uint32_t address, char *buffer, size_t maxlen)
{
	if (address == 0)
	{
		buffer[0] = 0;
		return;
	}
	memset(buffer, 0, maxlen);
	uc_mem_read(uc, address, (uint8_t*)buffer, maxlen - 1);
	buffer[maxlen - 1] = 0;
}

// Helper function to read unicode strings from emulator memory
static void ReadUnicodeStringFromEmulator(uc_engine *uc, uint32_t address, wchar_t *buffer, size_t maxlen)
{
	if (address == 0)
	{
		buffer[0] = 0;
		return;
	}
	memset(buffer, 0, maxlen * sizeof(wchar_t));
	uc_mem_read(uc, address, (uint8_t*)buffer, (maxlen - 1) * sizeof(wchar_t));
	buffer[maxlen - 1] = 0;
}

UNICORN_HOOK_FUNC(GetModuleFileNameW)
{
	uint32_t esp;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);

	// Parameters: hModule (ESP+4), lpFilename (ESP+8), nSize (ESP+12)
	uint32_t hModule;
	uint32_t lpFilename;
	uint32_t nSize;

	uc_mem_read(uc, esp + 4, &hModule, sizeof(hModule));
	uc_mem_read(uc, esp + 8, &lpFilename, sizeof(lpFilename));
	uc_mem_read(uc, esp + 12, &nSize, sizeof(nSize));

	// Get the module filename
	DWORD result = PeLdrGetModuleFileName((PE_HANDLE)hModule, (LPWSTR)lpFilename, nSize);

	// Return value in EAX
	uc_reg_write(uc, UC_X86_REG_EAX, &result);
}

UNICORN_HOOK_FUNC(GetModuleFileNameA)
{
	uint32_t esp;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);

	// Parameters: hModule (ESP+4), lpFilename (ESP+8), nSize (ESP+12)
	uint32_t hModule;
	uint32_t lpFilename;
	uint32_t nSize;

	uc_mem_read(uc, esp + 4, &hModule, sizeof(hModule));
	uc_mem_read(uc, esp + 8, &lpFilename, sizeof(lpFilename));
	uc_mem_read(uc, esp + 12, &nSize, sizeof(nSize));

	// Get the module filename
	DWORD result = PeLdrGetModuleFileNameA((PE_HANDLE)hModule, (LPSTR)lpFilename, nSize);

	// Return value in EAX
	uc_reg_write(uc, UC_X86_REG_EAX, &result);
}

UNICORN_HOOK_FUNC(GetModuleHandleA)
{
	uint32_t esp;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);

	// Parameter: lpModuleName (ESP+4)
	uint32_t lpModuleName;
	uc_mem_read(uc, esp + 4, &lpModuleName, sizeof(lpModuleName));

	wchar_t moduleName[MAX_PATH];
	if (lpModuleName == 0)
	{
		moduleName[0] = 0;
	}
	else
	{
		char ansiName[MAX_PATH];
		ReadStringFromEmulator(uc, lpModuleName, ansiName, MAX_PATH);
		// Convert ANSI to Unicode
		MultiByteToWideChar(CP_ACP, 0, ansiName, -1, moduleName, MAX_PATH);
	}

	PE_HANDLE result = PeLdrFindModule(moduleName);

	// Return value in EAX
	uint32_t resultAddr = (uint32_t)result;
	uc_reg_write(uc, UC_X86_REG_EAX, &resultAddr);
}

UNICORN_HOOK_FUNC(GetModuleHandleExA)
{
	uint32_t esp;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);

	// Parameters: dwFlags (ESP+4), lpModuleName (ESP+8), phModule (ESP+12)
	uint32_t dwFlags;
	uint32_t lpModuleName;
	uint32_t phModule;

	uc_mem_read(uc, esp + 4, &dwFlags, sizeof(dwFlags));
	uc_mem_read(uc, esp + 8, &lpModuleName, sizeof(lpModuleName));
	uc_mem_read(uc, esp + 12, &phModule, sizeof(phModule));

	wchar_t moduleName[MAX_PATH];
	if (lpModuleName == 0)
	{
		moduleName[0] = 0;
	}
	else
	{
		char ansiName[MAX_PATH];
		ReadStringFromEmulator(uc, lpModuleName, ansiName, MAX_PATH);
		MultiByteToWideChar(CP_ACP, 0, ansiName, -1, moduleName, MAX_PATH);
	}

	PE_HANDLE hModule = PeLdrFindModule(moduleName);
	
	// Write result to phModule
	uint32_t moduleAddr = (uint32_t)hModule;
	uc_mem_write(uc, phModule, &moduleAddr, sizeof(moduleAddr));

	// Return TRUE if found, FALSE otherwise
	BOOL result = (hModule != NULL);
	uc_reg_write(uc, UC_X86_REG_EAX, &result);
}

UNICORN_HOOK_FUNC(GetModuleHandleExW)
{
	uint32_t esp;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);

	// Parameters: dwFlags (ESP+4), lpModuleName (ESP+8), phModule (ESP+12)
	uint32_t dwFlags;
	uint32_t lpModuleName;
	uint32_t phModule;

	uc_mem_read(uc, esp + 4, &dwFlags, sizeof(dwFlags));
	uc_mem_read(uc, esp + 8, &lpModuleName, sizeof(lpModuleName));
	uc_mem_read(uc, esp + 12, &phModule, sizeof(phModule));

	wchar_t moduleName[MAX_PATH];
	if (lpModuleName == 0)
	{
		moduleName[0] = 0;
	}
	else
	{
		ReadUnicodeStringFromEmulator(uc, lpModuleName, moduleName, MAX_PATH);
	}

	PE_HANDLE hModule = PeLdrFindModule(moduleName);

	// Write result to phModule
	uint32_t moduleAddr = (uint32_t)hModule;
	uc_mem_write(uc, phModule, &moduleAddr, sizeof(moduleAddr));

	// Return TRUE if found, FALSE otherwise
	BOOL result = (hModule != NULL);
	uc_reg_write(uc, UC_X86_REG_EAX, &result);
}

UNICORN_HOOK_FUNC(GetModuleHandleW)
{
	uint32_t esp;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);

	// Parameter: lpModuleName (ESP+4)
	uint32_t lpModuleName;
	uc_mem_read(uc, esp + 4, &lpModuleName, sizeof(lpModuleName));

	wchar_t moduleName[MAX_PATH];
	if (lpModuleName == 0)
	{
		moduleName[0] = 0;
	}
	else
	{
		ReadUnicodeStringFromEmulator(uc, lpModuleName, moduleName, MAX_PATH);
	}

	PE_HANDLE result = PeLdrFindModule(moduleName);

	// Return value in EAX
	uint32_t resultAddr = (uint32_t)result;
	uc_reg_write(uc, UC_X86_REG_EAX, &resultAddr);
}

UNICORN_HOOK_FUNC(LoadLibraryA)
{
	uint32_t esp;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);

	// Parameter: lpLibFileName (ESP+4)
	uint32_t lpLibFileName;
	uc_mem_read(uc, esp + 4, &lpLibFileName, sizeof(lpLibFileName));

	char libFileName[MAX_PATH];
	ReadStringFromEmulator(uc, lpLibFileName, libFileName, MAX_PATH);

	// Load the library
	PE_HANDLE hModule = PeLdrLoadModuleA(libFileName, g_ExecMainCallback, g_ImportCallback);

	// Return value in EAX
	uint32_t resultAddr = (uint32_t)hModule;
	uc_reg_write(uc, UC_X86_REG_EAX, &resultAddr);
}

UNICORN_HOOK_FUNC(LoadLibraryExA)
{
	uint32_t esp;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);

	// Parameters: lpLibFileName (ESP+4), hFile (ESP+8), dwFlags (ESP+12)
	uint32_t lpLibFileName;
	uint32_t hFile;
	uint32_t dwFlags;

	uc_mem_read(uc, esp + 4, &lpLibFileName, sizeof(lpLibFileName));
	uc_mem_read(uc, esp + 8, &hFile, sizeof(hFile));
	uc_mem_read(uc, esp + 12, &dwFlags, sizeof(dwFlags));

	char libFileName[MAX_PATH];
	ReadStringFromEmulator(uc, lpLibFileName, libFileName, MAX_PATH);

	// For now, ignore hFile and dwFlags and just load normally
	// (full implementation would handle these parameters)
	PE_HANDLE hModule = PeLdrLoadModuleA(libFileName, g_ExecMainCallback, g_ImportCallback);

	// Return value in EAX
	uint32_t resultAddr = (uint32_t)hModule;
	uc_reg_write(uc, UC_X86_REG_EAX, &resultAddr);
}

UNICORN_HOOK_FUNC(LoadLibraryW)
{
	uint32_t esp;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);

	// Parameter: lpLibFileName (ESP+4)
	uint32_t lpLibFileName;
	uc_mem_read(uc, esp + 4, &lpLibFileName, sizeof(lpLibFileName));

	wchar_t libFileName[MAX_PATH];
	ReadUnicodeStringFromEmulator(uc, lpLibFileName, libFileName, MAX_PATH);

	// Load the library
	PE_HANDLE hModule = PeLdrLoadModule(libFileName, g_ExecMainCallback, g_ImportCallback);

	// Return value in EAX
	uint32_t resultAddr = (uint32_t)hModule;
	uc_reg_write(uc, UC_X86_REG_EAX, &resultAddr);
}

UNICORN_HOOK_FUNC(LoadLibraryExW)
{
	uint32_t esp;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);

	// Parameters: lpLibFileName (ESP+4), hFile (ESP+8), dwFlags (ESP+12)
	uint32_t lpLibFileName;
	uint32_t hFile;
	uint32_t dwFlags;

	uc_mem_read(uc, esp + 4, &lpLibFileName, sizeof(lpLibFileName));
	uc_mem_read(uc, esp + 8, &hFile, sizeof(hFile));
	uc_mem_read(uc, esp + 12, &dwFlags, sizeof(dwFlags));

	wchar_t libFileName[MAX_PATH];
	ReadUnicodeStringFromEmulator(uc, lpLibFileName, libFileName, MAX_PATH);

	// For now, ignore hFile and dwFlags and just load normally
	PE_HANDLE hModule = PeLdrLoadModule(libFileName, g_ExecMainCallback, g_ImportCallback);

	// Return value in EAX
	uint32_t resultAddr = (uint32_t)hModule;
	uc_reg_write(uc, UC_X86_REG_EAX, &resultAddr);
}

UNICORN_HOOK_FUNC(GetProcAddress)
{
	uint32_t esp;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);

	// Parameters: hModule (ESP+4), lpProcName (ESP+8)
	uint32_t hModule;
	uint32_t lpProcName;

	uc_mem_read(uc, esp + 4, &hModule, sizeof(hModule));
	uc_mem_read(uc, esp + 8, &lpProcName, sizeof(lpProcName));

	// Check if lpProcName is an ordinal (low value) or a string pointer
	FARPROC result = NULL;

	if (lpProcName < 0x10000)  // Likely an ordinal
	{
		// Convert ordinal to string format
		char ordinalStr[32];
		sprintf_s(ordinalStr, sizeof(ordinalStr), "Ord_%d", lpProcName);
		result = PeLdrGetProcAddressA((PE_HANDLE)hModule, ordinalStr, g_ExecMainCallback, g_ImportCallback);
	}
	else  // It's a pointer to a string
	{
		char procName[256];
		ReadStringFromEmulator(uc, lpProcName, procName, sizeof(procName));
		result = PeLdrGetProcAddressA((PE_HANDLE)hModule, procName, g_ExecMainCallback, g_ImportCallback);
	}

	// Return value in EAX
	uint32_t resultAddr = (uint32_t)result;
	uc_reg_write(uc, UC_X86_REG_EAX, &resultAddr);
}
