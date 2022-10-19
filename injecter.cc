#include "injecter.h"

int main() {
    IMAGE_DOS_HEADER *pDosHeader;
    IMAGE_NT_HEADERS64 *pNTHeader;
    CHAR filepath[MAX_PATH];
    std::cin >> filepath;
    LPVOID pImageBase;
    HANDLE hDll = NULL;
    if (hDll == NULL) {
        HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, 0);
        LPVOID pFile = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        printf("file map in %I64X\n", pFile);
        pDosHeader = (PIMAGE_DOS_HEADER)pFile;
        // std::cout << std::hex << pDosHeader->e_magic << std::endl;
        pNTHeader = (IMAGE_NT_HEADERS64 *)((char *)pFile + pDosHeader->e_lfanew);
        printf("NT Signature:%s\n", &(pNTHeader->Signature));
        pImageBase = VirtualAlloc(NULL, pNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        RtlZeroMemory(pImageBase, pNTHeader->OptionalHeader.SizeOfImage);
        printf("New image base:%I64X\n", pImageBase);
        MapSection(pDosHeader, pNTHeader, pImageBase);
        DoReloctionTable(pImageBase);
        DoImportTable(pImageBase);
        SetImageBaseAddr(pImageBase);
        std::cout << "Call dll main:" << CallDllMain(pImageBase) << std::endl;
    } else {
        pImageBase = (LPVOID)hDll;
    }
    // hDll = GetModuleHandleA(filepath);
    // pImageBase = (LPVOID)hDll;
    printf("Imagebase:%I64X\n", pImageBase);
    MessageBoxFunc mb = (MessageBoxFunc)GetFuncAddrByName(pImageBase, "MessageBoxA");
    getchar();
    getchar();

    mb(0, "text", "test", 0);
    // _add add = (_add)GetFuncAddrByName(pImageBase, "add");
    // if (add != NULL) {
    //     printf("1+2=%d\n", add(1, 2));
    // } else {
    //     printf("Get func addr failed\n");
    // }
    // getchar();

    return 0;
}

BOOL MapSection(PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS64 pNTHeader, LPVOID ImageBase) {
    WORD NumberOfSection = pNTHeader->FileHeader.NumberOfSections;
    DWORD dwSizeOfHeaders = pNTHeader->OptionalHeader.SizeOfHeaders;
    PIMAGE_SECTION_HEADER pSectionTableHeader = IMAGE_FIRST_SECTION(pNTHeader);
    RtlCopyMemory(ImageBase, (LPVOID)pDosHeader, dwSizeOfHeaders);
    LPVOID lpSrc = NULL;
    LPVOID lpDest = NULL;
    DWORD dwSizeOfRawData = 0;
    for (WORD i = 0; i < NumberOfSection; i++) {
        if (pSectionTableHeader->VirtualAddress == 0 || pSectionTableHeader->SizeOfRawData == 0) {
            pSectionTableHeader++;
            continue;
        }
        lpSrc = (LPVOID)((char *)pDosHeader + pSectionTableHeader->PointerToRawData);
        lpDest = (LPVOID)((char *)ImageBase + pSectionTableHeader->VirtualAddress);
        dwSizeOfRawData = pSectionTableHeader->SizeOfRawData;
        RtlCopyMemory(lpDest, lpSrc, dwSizeOfRawData);
        pSectionTableHeader++;
    }
    return TRUE;
}

BOOL DoReloctionTable(LPVOID lpBaseAddress) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
    PIMAGE_NT_HEADERS64 pNTHeader = (PIMAGE_NT_HEADERS64)((char *)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((char *)pDosHeader + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    printf("Reloc addr:%I64X\n", pReloc);
    if ((LPVOID)pReloc == (LPVOID)pDosHeader) {
        //没有重定位表
        return TRUE;
    }
    int nNumberOfReloc = 0;
    WORD *pRelocData = NULL;
    DWORD64 *pAddress = NULL;
    LPVOID pPageAddr = NULL;
    while (pReloc->VirtualAddress != 0 && pReloc->SizeOfBlock != 0) {
        nNumberOfReloc = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        pPageAddr = (LPVOID)(pReloc->VirtualAddress + (char *)lpBaseAddress);
        for (int i = 0; i < nNumberOfReloc; i++) {
            pRelocData = (WORD *)((char *)pReloc + sizeof(IMAGE_BASE_RELOCATION));
            if (((*(pRelocData + i) >> 12) & 0x000F) == 3 || ((*(pRelocData + i) >> 12) & 0x000F) == 0xA) {
                pAddress = (DWORD64 *)((char *)pPageAddr + (*(pRelocData + i) & 0x0FFF));
                *pAddress += (ULONGLONG)lpBaseAddress - pNTHeader->OptionalHeader.ImageBase;
            }
        }
        pReloc = (PIMAGE_BASE_RELOCATION)((char *)pReloc + pReloc->SizeOfBlock);
    }

    return TRUE;
}

BOOL DoImportTable(LPVOID lpBaseAddress) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
    PIMAGE_NT_HEADERS64 pNTHeader = (PIMAGE_NT_HEADERS64)((char *)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((char *)pDosHeader + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    char *pDllName = nullptr;
    HMODULE hDll = NULL;
    PIMAGE_THUNK_DATA pIat = NULL;
    FARPROC pFuncAddress = NULL;
    PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
    while (pImport->OriginalFirstThunk != 0) {
        pDllName = (char *)((char *)pDosHeader + pImport->Name);
        hDll = GetModuleHandleA(pDllName);
        if (hDll == NULL) {
            hDll = LoadLibraryA(pDllName);

            if (NULL == hDll) {
                printf("Loadlibrary failed, Dll name:%s\n", pDllName);
                pImport++;
                continue;
            }
            printf("Loadlibrary success, Dll name:%s\n", pDllName);
        }
        pIat = (PIMAGE_THUNK_DATA64)((char *)pDosHeader + pImport->FirstThunk);
        printf("from %s import func\tIAT addr:%I64X\n", pDllName, pIat);

        while (pIat->u1.Ordinal) {
            if (!IMAGE_SNAP_BY_ORDINAL64(pIat->u1.Ordinal)) {
                pImportByName = (PIMAGE_IMPORT_BY_NAME)((char *)pDosHeader + pIat->u1.AddressOfData);
                pFuncAddress = GetProcAddress(hDll, pImportByName->Name);
                printf("\timport func:%s\taddress:%I64X\n", pImportByName->Name, pFuncAddress);

            } else {
                pFuncAddress = GetProcAddress(hDll, (LPCSTR)(pIat->u1.Ordinal & IMAGE_ORDINAL_FLAG64));
                printf("\timport func ord:%I64Xaddress:%I64X\n", (LPCSTR)(pIat->u1.Ordinal & IMAGE_ORDINAL_FLAG64), pFuncAddress);
            }
            pIat->u1.Function = (ULONGLONG)pFuncAddress;
            pIat++;
        }
        pImport++;
    }
    return TRUE;
}

BOOL SetImageBaseAddr(LPVOID ImageBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    //获取NT头
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char *)pDosHeader + pDosHeader->e_lfanew);
    //修改默认加载基址
    pNtHeader->OptionalHeader.ImageBase = (ULONGLONG)ImageBase;
    return TRUE;
}

BOOL CallDllMain(LPVOID ImageBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    //获取NT头
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char *)pDosHeader + pDosHeader->e_lfanew);
    _DllMain dllmain = (_DllMain)((char *)pDosHeader + pNtHeader->OptionalHeader.AddressOfEntryPoint);
    return dllmain((HINSTANCE)ImageBase, DLL_PROCESS_ATTACH, NULL);
}

FARPROC GetFuncAddrByName(LPVOID DllImageBase, char *funcname) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)DllImageBase;
    //获取NT头
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char *)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (char *)DllImageBase);
    ULONGLONG *pFuncsArrAddr = NULL;
    ULONGLONG *pNamesArrAddr = NULL;
    ULONGLONG *pNameOrdArrAddr = NULL;
    WORD *pNameOrd = NULL;
    DWORD *pFuncRva = NULL;
    FARPROC pFunc = NULL;
    pFuncsArrAddr = (ULONGLONG *)((char *)DllImageBase + pExport->AddressOfFunctions);
    pNamesArrAddr = (ULONGLONG *)((char *)DllImageBase + pExport->AddressOfNames);
    pNameOrdArrAddr = (ULONGLONG *)((char *)DllImageBase + pExport->AddressOfNameOrdinals);
    printf("pFuncsArrAddr:%I64X\tpNamesArrAddr:%I64X\tpNameOrdArrAddr%I64X\n", pFuncsArrAddr, pNamesArrAddr, pNameOrdArrAddr);
    DWORD *pFuncNameRva;
    char *pFuncName;
    for (int i = 0; i < pExport->NumberOfNames; i++) {
        pFuncNameRva = (DWORD *)((char *)pNamesArrAddr + sizeof(DWORD) * i);
        pFuncName = (char *)((char *)DllImageBase + *pFuncNameRva);
        if (!strcmp(pFuncName, funcname)) {
            printf("find\n");
            pNameOrd = (WORD *)((char *)pNameOrdArrAddr + sizeof(WORD) * i);
            pFuncRva = (DWORD *)((char *)pFuncsArrAddr + (*pNameOrd) * 4);
            pFunc = (FARPROC)((char *)DllImageBase + *pFuncRva);
            printf("pNameOrd:%I64X\tfunc addr:%I64X\trva:%I64X\tfunc name:%s\n", pNameOrd, pFunc, *pFuncRva, pFuncName);
            return pFunc;
        }
    }
    return NULL;
}
