using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;

namespace NeverwhereInjector1
{
    public static class XenoWrapper
    {
        [DllImport("XenoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool initialize();

        [DllImport("XenoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void xeno_shutdown();

        [DllImport("XenoEngine.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void execute(string script);

        // Injection utility
        public static bool Inject()
        {
            var roblox = Process.GetProcessesByName("RobloxPlayerBeta");
            if (roblox.Length == 0)
            {
                MessageBox.Show("Roblox not found!", "Error");
                return false;
            }

            string dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "XenoEngine.dll");
            if (!File.Exists(dllPath))
            {
                MessageBox.Show("XenoEngine.dll missing!", "Error");
                return false;
            }

            // In a real scenario, we'd use the injector.hpp logic compiled into a separate utility or the main DLL
            // For now, we simulate the call to the stealth injection
            MessageBox.Show("Injecting XenoEngine.dll via Stealth Thread Hijacking...", "Status");
            return true; // Placeholder for actual injection success
        }
    }
}
