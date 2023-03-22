#include <Windows.h>
#include <iostream>

int main()
{
    const char* dllPath = "C:\\path\\to\\mydll.dll";
    const char* processName = "notepad.exe";

    
    DWORD processId = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry))
    {
        do {
            if (_stricmp(entry.szExeFile, processName) == 0)
            {
                processId = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);

    if (processId == 0)
    {
        std::cout << "Process not found\n";
        return 1;
    }

    
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (process == NULL)
    {
        std::cout << "Could not open process\n";
        return 1;
    }

    // Allocate memory in target process for DLL path
    LPVOID dllPathAddr = VirtualAllocEx(process, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (dllPathAddr == NULL)
    {
        std::cout << "Could not allocate memory in process\n";
        return 1;
    }

    
    if (!WriteProcessMemory(process, dllPathAddr, dllPath, strlen(dllPath) + 1, NULL))
    {
        std::cout << "Could not write to process memory\n";
        return 1;
    }

    
    HMODULE kernel32 = GetModuleHandle("kernel32.dll");
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(kernel32, "LoadLibraryA");
    if (loadLibraryAddr == NULL)
    {
        std::cout << "Could not get LoadLibrary address\n";
        return 1;
    }

    // Create remote thread to load DLL
    HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddr, 0, NULL);
    if (thread == NULL)
    {
        std::cout << "Could not create remote thread\n";
        return 1;
    }

    std::cout << "DLL injected successfully\n";

    
    CloseHandle(thread);
    VirtualFreeEx(process, dllPathAddr, 0, MEM_RELEASE);
    CloseHandle(process);

    return 0;
}
