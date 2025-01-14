#pragma once
#include <ntddk.h>

#define IO_GET_PROCESS_LIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1724, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_COPY_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1725, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_GET_PROCESS_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1726, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _KERNEL_PROCESS_LIST_OPERATION
{
    PVOID bufferAddress;
    INT32 bufferSize;
    INT32 processCount;
} KERNEL_PROCESS_LIST_OPERATION, * PKERNEL_PROCESS_LIST_OPERATION;

typedef struct _KERNEL_COPY_MEMORY_OPERATION
{
    INT64 targetProcessId;
    PVOID targetAddress;
    PVOID bufferAddress;
    INT32 bufferSize;
} KERNEL_COPY_MEMORY_OPERATION, * PKERNEL_COPY_MEMORY_OPERATION;

typedef struct _KERNEL_MODULES_LIST_OPERATION
{
    INT64 targetProcessId;
    PVOID bufferAddress;
    UINT32 bufferSize;
    UINT32 modulesCount;
} KERNEL_MODULES_LIST_OPERATION, * PKERNEL_MODULES_LIST_OPERATION;
