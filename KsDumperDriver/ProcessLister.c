#include "NTUndocumented.h"
#include "ProcessLister.h"
#include "Utility.h"
#include <ntstatus.h>

static PSYSTEM_PROCESS_INFORMATION GetRawProcessList()
{
    ULONG bufferSize = 0;
    PVOID bufferPtr = NULL;

    if (ZwQuerySystemInformation(SystemProcessInformation, 0, bufferSize, &bufferSize) == STATUS_INFO_LENGTH_MISMATCH)
    {
        bufferPtr = ExAllocatePoolZero(NonPagedPool, bufferSize, 'RPLI');

        if (bufferPtr != NULL)
        {
            if (ZwQuerySystemInformation(SystemProcessInformation, bufferPtr, bufferSize, &bufferSize) != STATUS_SUCCESS)
            {
                ExFreePool(bufferPtr);

                return (PSYSTEM_PROCESS_INFORMATION)NULL;
            }
        }
    }
    return (PSYSTEM_PROCESS_INFORMATION)bufferPtr;
}

static ULONG CalculateProcessListOutputSize(PSYSTEM_PROCESS_INFORMATION rawProcessList)
{
    int size = 0;

    while (rawProcessList->NextEntryOffset)
    {
        size += sizeof(PROCESS_SUMMARY);
        rawProcessList = (PSYSTEM_PROCESS_INFORMATION)(((CHAR*)rawProcessList) + rawProcessList->NextEntryOffset);
    }
    return size;
}

static PLDR_DATA_TABLE_ENTRY GetMainModuleDataTableEntry(PPEB64 peb)
{
    if (SanitizeUserPointer(peb, sizeof(PEB64)))
    {
        if (peb->Ldr)
        {
            if (SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA)))
            {
                if (!peb->Ldr->Initialized)
                {
                    int initLoadCount = 0;

                    while (!peb->Ldr->Initialized && initLoadCount++ < 4)
                    {
                        DriverSleep(250);
                    }
                }

                if (peb->Ldr->Initialized)
                {
                    return CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                }
            }
        }
    }
    return NULL;
}

static UINT32 GetProcessModulesCount(INT64 processId)
{
    KAPC_STATE state = { 0 };
    UINT32 moduleCount = 0;
    PEPROCESS targetProcess;

    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)processId, &targetProcess)))
    {
        KeStackAttachProcess((struct _KPROCESS*)targetProcess, (PRKAPC_STATE)&state);

        PPEB64 peb = (PPEB64)PsGetProcessPeb(targetProcess);
        if (SanitizeUserPointer(peb, sizeof(PEB64)) && SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA)) && peb->Ldr->Initialized && peb->Ldr->InMemoryOrderModuleList.Flink)
        {
            LIST_ENTRY* first;
            LIST_ENTRY* current;
            first = peb->Ldr->InLoadOrderModuleList.Flink;
            current = first;
            do
            {
                PLDR_DATA_TABLE_ENTRY mod_entry;

                mod_entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (!SanitizeUserPointer(mod_entry, sizeof(LDR_DATA_TABLE_ENTRY)))
                {
                    moduleCount = 0;
                    break;
                }

                moduleCount++;

                current = current->Flink;
            } while (current != first);
        }

        KeUnstackDetachProcess((PRKAPC_STATE)&state);
    }

    return moduleCount;
}

NTSTATUS GetProcessList(PVOID listedProcessBuffer, INT32 bufferSize, PINT32 requiredBufferSize, PINT32 processCount)
{
    PPROCESS_SUMMARY processSummary = (PPROCESS_SUMMARY)listedProcessBuffer;
    PSYSTEM_PROCESS_INFORMATION rawProcessList = GetRawProcessList();
    PVOID listHeadPointer = rawProcessList;
    *processCount = 0;

    if (rawProcessList)
    {
        int expectedBufferSize = CalculateProcessListOutputSize(rawProcessList);

        if (!listedProcessBuffer || bufferSize < expectedBufferSize)
        {
            *requiredBufferSize = expectedBufferSize;
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        if (!SanitizeUserPointer(listedProcessBuffer, bufferSize))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        while (rawProcessList->NextEntryOffset)
        {
            PEPROCESS targetProcess;
            KAPC_STATE state = { 0 };

            if (NT_SUCCESS(PsLookupProcessByProcessId(rawProcessList->UniqueProcessId, &targetProcess)))
            {
                PVOID mainModuleBase = NULL;
                PVOID mainModuleEntryPoint = NULL;
                UINT32 mainModuleImageSize = 0;
                PWCHAR mainModuleFileName = NULL;
                BOOLEAN isWow64 = 0;

                __try
                {
                    KeStackAttachProcess((struct _KPROCESS*)targetProcess, (PRKAPC_STATE)&state);

                    __try
                    {
                        mainModuleBase = PsGetProcessSectionBaseAddress(targetProcess);

                        if (mainModuleBase)
                        {
                            PPEB64 peb = (PPEB64)PsGetProcessPeb(targetProcess);

                            if (peb)
                            {
                                PLDR_DATA_TABLE_ENTRY mainModuleEntry = GetMainModuleDataTableEntry(peb);
                                mainModuleEntry = SanitizeUserPointer(mainModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY));

                                if (mainModuleEntry)
                                {
                                    mainModuleEntryPoint = mainModuleEntry->EntryPoint;
                                    mainModuleImageSize = mainModuleEntry->SizeOfImage;
                                    isWow64 = IS_WOW64_PE(mainModuleBase);

                                    mainModuleFileName = ExAllocatePoolZero(NonPagedPool, LOCAL_PATH_MAX * sizeof(WCHAR), 'FPLI');
                                    if (mainModuleFileName)
                                    {
                                        RtlZeroMemory(mainModuleFileName, LOCAL_PATH_MAX * sizeof(WCHAR));
                                        RtlCopyMemory(mainModuleFileName, mainModuleEntry->FullDllName.Buffer, LOCAL_PATH_MAX * sizeof(WCHAR));
                                    }
                                }
                            }
                        }
                    }
                    __except (GetExceptionCode())
                    {
                        DbgPrintEx(0, 0, "Peb Interaction Failed.\n");
                    }
                }
                __finally
                {
                    KeUnstackDetachProcess((PRKAPC_STATE)&state);
                }

                if (mainModuleFileName)
                {

                    RtlCopyMemory(processSummary->MainModuleFileName, mainModuleFileName, LOCAL_PATH_MAX * sizeof(WCHAR));
                    ExFreePool(mainModuleFileName);

                    processSummary->ProcessId = (INT64)rawProcessList->UniqueProcessId;
                    processSummary->MainModuleBase = mainModuleBase;
                    processSummary->MainModuleEntryPoint = mainModuleEntryPoint;
                    processSummary->MainModuleImageSize = mainModuleImageSize;
                    processSummary->WOW64 = isWow64;

                    processSummary++;
                    (*processCount)++;
                }

                ObDereferenceObject(targetProcess);
            }

            rawProcessList = (PSYSTEM_PROCESS_INFORMATION)(((CHAR*)rawProcessList) + rawProcessList->NextEntryOffset);
        }

        ExFreePool(listHeadPointer);
        return STATUS_SUCCESS;
    }

    return STATUS_RETRY;
}

NTSTATUS GetProcessModulesList(INT64 processId, PVOID listedModulesBuffer, UINT32 bufferSize, PUINT32 bufferSizeOut, PUINT32 modulesCount)
{
    PEPROCESS targetProcess;
    KAPC_STATE state = { 0 };
    UINT32 moduleCount;
    UINT32 current_module_number = 0;
    PMODULE_SUMMARY outModuleInfo;
    PVOID buffer;

    moduleCount = GetProcessModulesCount(processId);

    if (!moduleCount)
    {
        return STATUS_RETRY;
    }

    if (moduleCount * sizeof(MODULE_SUMMARY) > bufferSize || !listedModulesBuffer)
    {
        *bufferSizeOut = moduleCount * sizeof(MODULE_SUMMARY);
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!SanitizeUserPointer(listedModulesBuffer, bufferSize))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    NTSTATUS ret = STATUS_RETRY;

    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)processId, &targetProcess)))
    {
        KeStackAttachProcess((struct _KPROCESS*)targetProcess, (PRKAPC_STATE)&state);

        buffer = ExAllocatePoolZero(NonPagedPool, moduleCount * sizeof(MODULE_SUMMARY), 'AMLI');
        if (!buffer)
        {
            KeUnstackDetachProcess((PRKAPC_STATE)&state);
            return STATUS_RETRY;
        }
        outModuleInfo = buffer;

        ret = STATUS_SUCCESS;
        PPEB64 peb = (PPEB64)PsGetProcessPeb(targetProcess);
        if (SanitizeUserPointer(peb, sizeof(PEB64)) && SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA)) && peb->Ldr->Initialized && peb->Ldr->InMemoryOrderModuleList.Flink)
        {
            LIST_ENTRY* first;
            LIST_ENTRY* current;

            first = peb->Ldr->InLoadOrderModuleList.Flink;
            current = first;
            for(current_module_number=0; current_module_number< moduleCount; ++current_module_number)
            {
                PLDR_DATA_TABLE_ENTRY mod_entry;

                mod_entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (!SanitizeUserPointer(mod_entry, sizeof(LDR_DATA_TABLE_ENTRY)))
                {
                    ret = STATUS_RETRY;
                    break;
                }

                if (mod_entry->FullDllName.Length > 1 && SanitizeUserPointer(mod_entry->FullDllName.Buffer, mod_entry->FullDllName.Length))
                {
                    RtlCopyMemory(outModuleInfo->FullDllName, mod_entry->FullDllName.Buffer, min(LOCAL_PATH_MAX * sizeof(WCHAR), mod_entry->FullDllName.Length));
                }

                if (mod_entry->BaseDllName.Length > 1 && SanitizeUserPointer(mod_entry->BaseDllName.Buffer, mod_entry->BaseDllName.Length))
                {
                    RtlCopyMemory(outModuleInfo->BaseDllName, mod_entry->BaseDllName.Buffer, min(LOCAL_PATH_MAX * sizeof(WCHAR), mod_entry->BaseDllName.Length));
                }

                outModuleInfo->DllBase = mod_entry->DllBase;
                outModuleInfo->SizeOfImage = mod_entry->SizeOfImage;

                outModuleInfo++;

                current = current->Flink;

                if (current == first)
                {
                    ret = STATUS_RETRY;
                    break;
                }
            }
        }
        KeUnstackDetachProcess((PRKAPC_STATE)&state);

        *modulesCount = current_module_number;
        RtlCopyMemory(listedModulesBuffer, buffer, moduleCount * sizeof(MODULE_SUMMARY));
        ExFreePool(buffer);
    }

    return ret;
}