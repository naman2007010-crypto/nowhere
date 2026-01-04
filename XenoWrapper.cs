using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;

namespace NowhereInjector1
{
    public static class XenoWrapper
    {
        [DllImport("XenoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool initialize();

        [DllImport("XenoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void xeno_shutdown();

        [DllImport("XenoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void execute(string script);

        [DllImport("XenoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool RefreshState();

        [DllImport("XenoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GetLuaState();

        [DllImport("XenoEngine.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public static extern bool InjectIntoProcess(uint processId, [MarshalAs(UnmanagedType.LPWStr)] string dllPath);

        // Injection utility - uses manual mapping via the native DLL
        public static bool Inject()
        {
            var robloxProcesses = Process.GetProcessesByName("RobloxPlayerBeta");
            if (robloxProcesses.Length == 0)
            {
                MessageBox.Show("Roblox not found! Please launch Roblox first.", "Nowhere Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            string dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "XenoEngine.dll");
            if (!File.Exists(dllPath))
            {
                MessageBox.Show("XenoEngine.dll is missing from the application folder!", "Nowhere Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            try
            {
                uint targetPid = (uint)robloxProcesses[0].Id;
                bool success = InjectIntoProcess(targetPid, dllPath);

                if (success)
                {
                    MessageBox.Show("Injection successful! Engine initialized.", "Nowhere", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return true;
                }
                else
                {
                    MessageBox.Show("Injection failed. Check if Roblox is running with admin privileges.", "Nowhere Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return false;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Injection error: {ex.Message}", "Nowhere Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }
    }
}
