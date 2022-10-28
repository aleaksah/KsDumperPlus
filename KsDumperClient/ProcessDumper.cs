using System;
using System.IO;
using System.Runtime.InteropServices;
using KsDumperClient.Driver;
using KsDumperClient.PE;
using KsDumperClient.Utility;

using static KsDumperClient.PE.NativePEStructs;

namespace KsDumperClient
{
    public class ProcessDumper
    {
        private DriverInterface kernelDriver;

        public ProcessDumper(DriverInterface kernelDriver)
        {
            this.kernelDriver = kernelDriver;
        }

        public bool DumpProcess(ProcessSummary processSummary, out PEFile outputFile)
        {
            IntPtr basePointer = (IntPtr)processSummary.MainModuleBase;
            IMAGE_DOS_HEADER dosHeader = ReadProcessStruct<IMAGE_DOS_HEADER>(processSummary.ProcessId, basePointer);
            outputFile = default(PEFile);

            Logger.SkipLine();
            Logger.Log("Targeting Process: {0} ({1})", processSummary.ProcessName, processSummary.ProcessId);

            if (dosHeader.IsValid)
            {                
                IntPtr peHeaderPointer = basePointer + dosHeader.e_lfanew;
                Logger.Log("PE Header Found: 0x{0:x8}", peHeaderPointer.ToInt64());

                IntPtr dosStubPointer = basePointer + Marshal.SizeOf<IMAGE_DOS_HEADER>();
                byte[] dosStub = ReadProcessBytes(processSummary.ProcessId, dosStubPointer, dosHeader.e_lfanew - Marshal.SizeOf<IMAGE_DOS_HEADER>());

                PEFile peFile;

                if (!processSummary.IsWOW64)
                {
                    peFile = Dump64BitPE(processSummary.ProcessId, dosHeader, dosStub, peHeaderPointer);
                }
                else
                {
                    peFile = Dump32BitPE(processSummary.ProcessId, dosHeader, dosStub, peHeaderPointer);
                }

                if (peFile != default(PEFile))
                {
                    IntPtr sectionHeaderPointer = peHeaderPointer + peFile.GetFirstSectionHeaderOffset();
                    
                    Logger.Log("Header is valid ({0}) !", peFile.Type);
                    Logger.Log("Parsing {0} Sections...", peFile.Sections.Length);

                    for (int i = 0; i < peFile.Sections.Length; i++)
                    {
                        IMAGE_SECTION_HEADER sectionHeader = ReadProcessStruct<IMAGE_SECTION_HEADER>(processSummary.ProcessId, sectionHeaderPointer);
                        peFile.Sections[i] = new PESection
                        {
                            Header = PESection.PESectionHeader.FromNativeStruct(sectionHeader),
                            InitialSize = (int)sectionHeader.VirtualSize
                        };

                        ReadSectionContent(processSummary.ProcessId, new IntPtr(basePointer.ToInt64() + sectionHeader.VirtualAddress), peFile.Sections[i]);
                        sectionHeaderPointer += Marshal.SizeOf<IMAGE_SECTION_HEADER>();
                    }

                    Logger.Log("Aligning Sections...");
                    peFile.AlignSectionHeaders();

                    Logger.Log("Fixing PE Header...");
                    peFile.FixPEHeader();

                    Logger.Log("Dump Completed !");
                    outputFile = peFile;
                    return true;
                }
                else
                {
                    Logger.Log("Bad PE Header !");
                }
            }
            return false;
        }

        public bool DumpProcessPriveteMem(ProcessSummary processSummary, string out_directory)
        {
            IntPtr process_handle = WinApi.OpenProcess(WinApi.PROCESS_QUERY_INFORMATION | WinApi.PROCESS_VM_READ, WinApi.FALSE, (int)processSummary.ProcessId);
            if (process_handle == null)
            {
                return false;
            }

            // Windows 32bit limit: 0xFFFFFFFF
            // Windows 64bit limit: 0x7FFFFFFFFFF
            WinApi.MEMORY_BASIC_INFORMATION m;
            long MaxAddress = 0x7FFFFFFFFFF;
            long address = 0;

            while (address < MaxAddress)
            {
                int ret;
                ret = WinApi.VirtualQueryEx(process_handle, (IntPtr)address, out m, (uint)Marshal.SizeOf(typeof(WinApi.MEMORY_BASIC_INFORMATION)));
                if (ret != (uint)Marshal.SizeOf(typeof(WinApi.MEMORY_BASIC_INFORMATION)))
                {
                    return false;
                }

                bool valid_chunk = true;

                if ((m.Type & WinApi.MEM_PRIVATE) == 0)
                {
                    //Logger.Log("Skipping, MEM_PRIVATE flag not set");
                    valid_chunk = false;
                }
                else if((m.Protect & WinApi.PAGE_NOACCESS) == WinApi.PAGE_NOACCESS)
                {
                    //Logger.Log("Skipping, PAGE_NOACCESS flag set");
                    valid_chunk = false;
                }
                else if((m.State & WinApi.MEM_COMMIT) == 0)
                {
                    //Logger.Log("Skipping, MEM_COMMIT flag not set");
                    valid_chunk = false;
                }
                else if((long)m.RegionSize > ((long)1024 * 1024 * 1024 * 2 + 1024 * 1024))
                {
                    //Logger.Log("Skipping, chunk too big");
                    valid_chunk = false;
                }

                if (valid_chunk)
                {
                    Logger.Log("Found chunk " + m.BaseAddress + ", size: " + m.RegionSize);

                    string out_file = out_directory + "\\" + m.BaseAddress.ToString() + ".bin";
                    if (!DumpProcessPriveteRegionToFile(processSummary, m.BaseAddress, (long)m.RegionSize, out_file))
                    {
                        WinApi.CloseHandle(process_handle);
                        return false;
                    }
                    //GC.Collect();//eh?
                }

                address += (long)m.RegionSize;
            }

            WinApi.CloseHandle(process_handle);

            return true;
        }

        private bool DumpProcessPriveteRegionToFile(ProcessSummary processSummary, IntPtr baseAddr, long length, string filename)
        {
            long collected = 0;
            int maximum_one_time_chunk = 512 * 1024 * 1024;
            BinaryWriter Writer = new BinaryWriter(File.OpenWrite(filename));

            while (collected < length)
            {
                byte[] mem;
                int to_read;

                if (length - collected > maximum_one_time_chunk)
                {
                    to_read = maximum_one_time_chunk;
                }
                else
                {
                    to_read = (int)(length - collected);
                }

                mem = ReadProcessBytes(processSummary.ProcessId, (IntPtr)((long)baseAddr + collected), to_read);
                if (mem.Length != to_read)
                {
                    Writer.Close();
                    return false;
                }

                collected += mem.Length;

                Logger.Log(collected + "/" + length + " bytes saved");

                Writer.Write(mem);
                Writer.Flush();
            }
            Writer.Close();
            return true;
        }

        private PEFile Dump64BitPE(long processId, IMAGE_DOS_HEADER dosHeader, byte[] dosStub, IntPtr peHeaderPointer)
        {
            IMAGE_NT_HEADERS64 peHeader = ReadProcessStruct<IMAGE_NT_HEADERS64>(processId, peHeaderPointer);

            if (peHeader.IsValid)
            {
                return new PE64File(dosHeader, peHeader, dosStub);
            }
            return default(PEFile);
        }

        private PEFile Dump32BitPE(long processId, IMAGE_DOS_HEADER dosHeader, byte[] dosStub, IntPtr peHeaderPointer)
        {
            IMAGE_NT_HEADERS32 peHeader = ReadProcessStruct<IMAGE_NT_HEADERS32>(processId, peHeaderPointer);

            if (peHeader.IsValid)
            {
                return new PE32File(dosHeader, peHeader, dosStub);
            }
            return default(PEFile);
        }

        private T ReadProcessStruct<T>(long processId, IntPtr address) where T : struct
        {
            IntPtr buffer = MarshalUtility.AllocEmptyStruct<T>();

            if (kernelDriver.CopyVirtualMemory(processId, address, buffer, Marshal.SizeOf<T>()))
            {
                return MarshalUtility.GetStructFromMemory<T>(buffer);
            }
            return default(T);
        }

        private bool ReadSectionContent(long processId, IntPtr sectionPointer, PESection section)
        {
            const int maxReadSize = 100;
            int readSize = section.InitialSize;

            if (sectionPointer == IntPtr.Zero || readSize == 0)
            {
                return true;
            }

            if (readSize <= maxReadSize)
            {
                section.DataSize = readSize;
                section.Content = ReadProcessBytes(processId, sectionPointer, readSize);

                return true;
            }
            else
            {
                CalculateRealSectionSize(processId, sectionPointer, section);

                if (section.DataSize != 0)
                {
                    section.Content = ReadProcessBytes(processId, sectionPointer, section.DataSize);
                    return true;
                }
            }
            return false;
        }

        private byte[] ReadProcessBytes(long processId, IntPtr address, int size)
        {
            IntPtr unmanagedBytePointer = MarshalUtility.AllocZeroFilled(size);
            kernelDriver.CopyVirtualMemory(processId, address, unmanagedBytePointer, size);

            byte[] buffer = new byte[size];
            Marshal.Copy(unmanagedBytePointer, buffer, 0, size);
            Marshal.FreeHGlobal(unmanagedBytePointer);

            return buffer;
        }

        private void CalculateRealSectionSize(long processId, IntPtr sectionPointer, PESection section)
        {
            const int maxReadSize = 100;
            int readSize = section.InitialSize;
            int currentReadSize = readSize % maxReadSize;

            if (currentReadSize == 0)
            {
                currentReadSize = maxReadSize;
            }
            IntPtr currentOffset = sectionPointer + readSize - currentReadSize;

            while (currentOffset.ToInt64() >= sectionPointer.ToInt64())
            {
                byte[] buffer = ReadProcessBytes(processId, currentOffset, currentReadSize);
                int codeByteCount = GetInstructionByteCount(buffer);

                if (codeByteCount != 0)
                {
                    currentOffset += codeByteCount;

                    if (sectionPointer.ToInt64() < currentOffset.ToInt64())
                    {
                        section.DataSize = (int)(currentOffset.ToInt64() - sectionPointer.ToInt64());
                        section.DataSize += 4;

                        if (section.InitialSize < section.DataSize)
                        {
                            section.DataSize = section.InitialSize;
                        }
                    }
                    break;
                }

                currentReadSize = maxReadSize;
                currentOffset -= currentReadSize;
            }
        }
        
        private int GetInstructionByteCount(byte[] dataBlock)
        {
            for (int i = (dataBlock.Length - 1); i >= 0; i--)
            {
                if (dataBlock[i] != 0)
                {
                    return i + 1;
                }
            }
            return 0;
        }
    }
}
