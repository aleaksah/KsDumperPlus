using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace KsDumperClient
{
    public class ModuleSummary
    {
        public ulong DllBase { get; private set; }
        public ulong SizeOfImage { get; private set; }
        public string FullDllName { get; private set; }
        public string BaseDllName { get; private set; }

        private ModuleSummary(ulong dllBase, ulong sizeOfImage, string fullDllName, string baseDllName)
        {
            DllBase = dllBase;
            SizeOfImage = sizeOfImage;
            FullDllName = fullDllName;
            BaseDllName = baseDllName;
        }

        public static ModuleSummary FromStream(BinaryReader reader)
        {
            return new ModuleSummary
            (
                reader.ReadUInt64(),
                reader.ReadUInt32(),
                Encoding.Unicode.GetString(reader.ReadBytes(260 * 2)).Split('\0')[0],
                Encoding.Unicode.GetString(reader.ReadBytes(260 * 2)).Split('\0')[0]
            );
        }
    }
}
