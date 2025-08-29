#include <ntddk.h>


#define FILE_DEVICE_LEAKLESS  0x8000     
#define IOCTL_LEAKLESS_GET_VERSION \
    CTL_CODE(FILE_DEVICE_LEAKLESS, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_LEAKLESS_INC \
    CTL_CODE(FILE_DEVICE_LEAKLESS, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define FLAG_MAX 512

static CHAR  g_FlagBuf[FLAG_MAX] = { 0 };
static ULONG g_FlagSize = 0;
PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_SymbolicLink;

void LeakLessUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS LeakLessCreateClose(_In_ PDEVICE_OBJECT Device, _In_ PIRP Irp);
NTSTATUS LeakLessDeviceControl(_In_ PDEVICE_OBJECT Device, _In_ PIRP Irp);

struct UserParm {
    ULONG64 UserPtr;
    size_t size;
};

NTSTATUS
LeakLessCreateClose(PDEVICE_OBJECT Device, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Device);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

void LeakLessUnload(PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&g_SymbolicLink);
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS
LeakLessDeviceControl(PDEVICE_OBJECT Device, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Device);

    PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS            status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR           info = 0;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_LEAKLESS_GET_VERSION:
    {
        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(PULONG)Irp->AssociatedIrp.SystemBuffer = 0x0001'0000;
        info = sizeof(ULONG);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_LEAKLESS_INC:
    {
        ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;

        if (inLen < 8) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PVOID UserPtr  = (PVOID)*(ULONG64*)Irp->AssociatedIrp.SystemBuffer;
        struct UserParm* user_parm = NULL;
        PMDL pmdl = NULL;
        PVOID sysVa = NULL;
        if (MmIsAddressValid(UserPtr)) {
            pmdl = IoAllocateMdl(UserPtr, 0x10, 0, 0, 0);
            if (!pmdl) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            __try {
                MmProbeAndLockPages(pmdl,
                    Irp->RequestorMode,         
                    IoReadAccess);    
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
                IoFreeMdl(pmdl);
                break;
            }
            sysVa = MmMapLockedPagesSpecifyCache(
                pmdl,
                KernelMode,           
                MmCached,             
                NULL,                 
                FALSE,               
                NormalPagePriority);
            if (!sysVa) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                MmUnlockPages(pmdl);
                IoFreeMdl(pmdl);
                break;
            }
            user_parm = (struct UserParm*)sysVa;
            __try {
                ProbeForWrite((void*)user_parm->UserPtr, 8, 4);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
                MmUnmapLockedPages(sysVa, pmdl);
                MmUnlockPages(pmdl);
                IoFreeMdl(pmdl);
                break;
            }
            InterlockedIncrement((volatile LONG *)user_parm->UserPtr);
            MmUnmapLockedPages(sysVa, pmdl);
            MmUnlockPages(pmdl);
            IoFreeMdl(pmdl);
            status = STATUS_SUCCESS;


        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }

        info = 0;
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS NTAPI
DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\LeakLess");
    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\LeakLess");
    UNICODE_STRING path = RTL_CONSTANT_STRING(L"\\??\\C:\\flag.txt");
    OBJECT_ATTRIBUTES oa;
    HANDLE             hFile = NULL;
    IO_STATUS_BLOCK    iosb = { 0 };

    status = IoCreateDevice(
        DriverObject,
        0,                  
        &devName,
        FILE_DEVICE_LEAKLESS,
        0,
        FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(status))
        return status;

    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }
    g_SymbolicLink = symName;


    DriverObject->MajorFunction[IRP_MJ_CREATE] =
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = LeakLessCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = LeakLessDeviceControl;
    DriverObject->DriverUnload = LeakLessUnload;

    InitializeObjectAttributes(&oa, &path,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, NULL);

    status = ZwCreateFile(&hFile,
        GENERIC_READ | DELETE | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,                        
        FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_NON_DIRECTORY_FILE,
        NULL, 0);

    if (NT_SUCCESS(status))
    {
        
        status = ZwReadFile(hFile,
            NULL, NULL, NULL,
            &iosb,
            g_FlagBuf,
            FLAG_MAX - 1,   
            NULL, NULL);

        if (NT_SUCCESS(status))
            g_FlagSize = (ULONG)iosb.Information;

        FILE_DISPOSITION_INFORMATION disp = { TRUE };
        ZwSetInformationFile(hFile, &iosb,
            &disp, sizeof(disp),
            FileDispositionInformation);

        ZwClose(hFile);
    }

    return STATUS_SUCCESS;
}