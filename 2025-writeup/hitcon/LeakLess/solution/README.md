# The Intended Solution for LeakLess

## Description

This is a simple WDM driver. When loaded, it reads the contents of `C:\flag.txt` into memory and provides two IOCTL: `IOCTL_LEAKLESS_TEST` and `IOCTL_LEAKLESS_INC`. The `IOCTL_LEAKLESS_TEST` is used only for testing, while `IOCTL_LEAKLESS_INC` increments the value at a pointer address supplied by the user.

```cpp=

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

    if (MmIsAddressValid(UserPtr)) { //------------[1]
        pmdl = IoAllocateMdl(UserPtr, 0x10, 0, 0, 0);
        if (!pmdl) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        __try {
            MmProbeAndLockPages(pmdl, Irp->RequestorMode, IoReadAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            IoFreeMdl(pmdl);
            break;
        }

        sysVa = MmMapLockedPagesSpecifyCache(pmdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
        if (!sysVa) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            MmUnlockPages(pmdl);
            IoFreeMdl(pmdl);
            break;
        }

        user_parm = (struct UserParm*)sysVa;
        __try {
            ProbeForWrite((void*)user_parm->UserPtr, 8, 4); //----[2]
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            MmUnmapLockedPages(sysVa, pmdl);
            MmUnlockPages(pmdl);
            IoFreeMdl(pmdl);
            break;
        }

        InterlockedIncrement((volatile LONG *)user_parm->UserPtr); //------[3]
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

```
## Vulnerability

This driver contains two vulnerabilities, both within `IOCTL_LEAKLESS_INC`:

1. At [1], the driver uses [`MmIsAddressValid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmisaddressvalid) to check the validity(page fault) of a user-supplied pointer. Depending on the result, it returns two different error codes. This allows users to perform a side-channel attack to leak the kernel base address.

2. The second vulnerability is a `Double Fetch` issue. After verifying the pointer at [2] using `ProbeForWrite`, the pointer is fetched again at [3]. By exploiting this race condition, a user can modify the pointer to an arbitrary kernel address, resulting in an arbitrary increment primitive.

## Exploitation

1. Initially, by providing various kernel addresses to `MmIsAddressValid`, an attacker can determine if specific kernel addresses are mapped in memory. The NT kernel typically resides within the address range `0xfffff80000000000` - `0xfffff80800000000`. By probing these addresses, one can identify the NT kernel address. Usually, the NT kernel can be found at the second mapped region.

2. With the kernel base address known, the attacker leverages the arbitrary increment vulnerability to modify `nt!SeDebugPrivilege` from 0x14 to 0x17. More details on this method can be found in [our blog post](https://devco.re/blog/2024/10/05/streaming-vulnerabilities-from-windows-kernel-proxying-to-kernel-part2-en/#lets-find-a-new-way-).

3. After modifying `nt!SeDebugPrivilege` to 0x17, a normal user gains `SeDebugPrivilege`. This elevated privilege enables the user to invoke APIs like `NtQuerySystemInformation` to leak addresses of objects in the 24H2 version of Windows in Medium IL. The attacker can then use this information to obtain the address of [I/O Ring](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/) and subsequently exploit the arbitrary increment primitive to achieve arbitrary memory reads. After that, you can read the flag from the kernel memory.