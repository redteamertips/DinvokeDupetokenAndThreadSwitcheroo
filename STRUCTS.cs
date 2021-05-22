using System;
using System.Runtime.InteropServices;


/*
 * These strucs are not part of Dinvoke yet but will be in the future
 */
namespace DInvokeDupeTokenAndThreatSwitcheroo
{
    public class STRUCTS
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [Flags]
        public enum ProcThreadAttribute : int
        {
            MITIGATION_POLICY = 0x20007,
            PARENT_PROCESS = 0x00020000
        }

        [Flags]
        public enum BinarySignaturePolicy : ulong
        {
            BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000,
        }

        [Flags]
        public enum CreationFlags : uint
        {
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_SUSPENDED = 0x00000004
        }

        [Flags]
        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        [Flags]
        public enum TOKEN_TYPE
        {
            TokenPrimary,
            TokenImpersonation
        }
    }
}
