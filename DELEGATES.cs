using System;
using System.Runtime.InteropServices;
using DInvoke.Data;

/*
 * These delegates are not part of Dinvoke yet, but will be sooner or later.
 */
namespace DInvokeDupeTokenAndThreatSwitcheroo
{
    public class DELEGATES
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcessEx(
            string lpApplicationName,
            string lpCommandLine,
            ref STRUCTS.SECURITY_ATTRIBUTES lpProcessAttributes,
            ref STRUCTS.SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            STRUCTS.CreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STRUCTS.STARTUPINFOEX lpStartupInfo,
            out STRUCTS.PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref STRUCTS.SECURITY_ATTRIBUTES lpProcessAttributes,
            ref STRUCTS.SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            STRUCTS.CreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STRUCTS.STARTUPINFO lpStartupInfo,
            out STRUCTS.PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DeleteProcThreadAttributeList(
            IntPtr lpAttributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref STRUCTS.SECURITY_ATTRIBUTES lpTokenAttributes,
            STRUCTS.SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            Win32.WinNT.TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcessAsUserEx(
                IntPtr hToken,
                string lpApplicationName,
                string lpCommandLine,
                ref STRUCTS.SECURITY_ATTRIBUTES lpProcessAttributes,
                ref STRUCTS.SECURITY_ATTRIBUTES lpThreadAttributes,
                bool bInheritHandles,
                uint dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                ref STRUCTS.STARTUPINFOEX lpStartupInfoex,
                out STRUCTS.PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 TerminateThread(IntPtr hThread);
    }
}
