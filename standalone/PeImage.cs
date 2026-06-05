using System;
using System.Collections.Generic;
using System.IO;

namespace OffsetRecovery.Standalone
{
    // Minimal PE32+ reader. We parse only what the recovery needs:
    //   - image base, section table (for the virtual memory model)
    //   - the exception directory (.pdata RUNTIME_FUNCTION table) for function bounds
    // No external PE dependency on purpose: the format details we touch are stable
    // and hand-rolling keeps the PoC self-contained behind a single NuGet (Iced).
    public sealed class PeImage
    {
        public sealed class Section
        {
            public string Name;
            public ulong VirtualStart;   // absolute VA (image base + RVA)
            public ulong VirtualEnd;      // exclusive, by max(virtualSize, rawSize)
            public byte[] Raw;            // initialized bytes (length == rawSize)
            public bool Executable;
            public bool Readable;
        }

        public sealed class RuntimeFunction
        {
            public ulong Begin;  // absolute VA
            public ulong End;    // absolute VA, exclusive
        }

        public ulong ImageBase { get; private set; }
        public ulong EntryPoint { get; private set; }
        public IReadOnlyList<Section> Sections => _sections;
        public IReadOnlyList<RuntimeFunction> RuntimeFunctions => _runtimeFunctions;

        private readonly List<Section> _sections = new List<Section>();
        private readonly List<RuntimeFunction> _runtimeFunctions = new List<RuntimeFunction>();

        public static PeImage Load(string path)
        {
            byte[] file = File.ReadAllBytes(path);
            var image = new PeImage();
            image.Parse(file);
            return image;
        }

        private void Parse(byte[] file)
        {
            if (file.Length < 0x40 || file[0] != 'M' || file[1] != 'Z')
            {
                throw new InvalidDataException("Not an MZ/PE file.");
            }

            int peOffset = BitConverter.ToInt32(file, 0x3C);
            if (file[peOffset] != 'P' || file[peOffset + 1] != 'E')
            {
                throw new InvalidDataException("Missing PE signature.");
            }

            int coff = peOffset + 4;
            int numberOfSections = BitConverter.ToUInt16(file, coff + 2);
            int sizeOfOptionalHeader = BitConverter.ToUInt16(file, coff + 16);
            int opt = coff + 20;

            ushort magic = BitConverter.ToUInt16(file, opt + 0);
            if (magic != 0x20B)
            {
                throw new InvalidDataException("Only PE32+ (x64) is supported by this PoC.");
            }

            EntryPoint = BitConverter.ToUInt32(file, opt + 16);
            ImageBase = BitConverter.ToUInt64(file, opt + 24);
            EntryPoint += ImageBase;

            int numberOfRvaAndSizes = BitConverter.ToInt32(file, opt + 108);
            int dataDirectory = opt + 112;

            uint exceptionRva = 0;
            uint exceptionSize = 0;
            if (numberOfRvaAndSizes > 3)
            {
                exceptionRva = BitConverter.ToUInt32(file, dataDirectory + 3 * 8);
                exceptionSize = BitConverter.ToUInt32(file, dataDirectory + 3 * 8 + 4);
            }

            int sectionTable = opt + sizeOfOptionalHeader;
            for (int i = 0; i < numberOfSections; i++)
            {
                int entry = sectionTable + i * 40;
                string name = ReadSectionName(file, entry);
                uint virtualSize = BitConverter.ToUInt32(file, entry + 8);
                uint virtualAddress = BitConverter.ToUInt32(file, entry + 12);
                uint sizeOfRawData = BitConverter.ToUInt32(file, entry + 16);
                uint pointerToRawData = BitConverter.ToUInt32(file, entry + 20);
                uint characteristics = BitConverter.ToUInt32(file, entry + 36);

                byte[] raw = new byte[sizeOfRawData];
                if (pointerToRawData != 0 && sizeOfRawData != 0)
                {
                    int copy = (int)Math.Min(sizeOfRawData, (uint)(file.Length - pointerToRawData));
                    Array.Copy(file, pointerToRawData, raw, 0, Math.Max(0, copy));
                }

                ulong virtualStart = ImageBase + virtualAddress;
                ulong span = Math.Max(virtualSize, sizeOfRawData);
                _sections.Add(new Section
                {
                    Name = name,
                    VirtualStart = virtualStart,
                    VirtualEnd = virtualStart + span,
                    Raw = raw,
                    Executable = (characteristics & 0x20000000u) != 0,
                    Readable = (characteristics & 0x40000000u) != 0,
                });
            }

            ParseExceptionDirectory(exceptionRva, exceptionSize);
        }

        private void ParseExceptionDirectory(uint exceptionRva, uint exceptionSize)
        {
            if (exceptionRva == 0 || exceptionSize == 0)
            {
                return;
            }

            ulong tableVa = ImageBase + exceptionRva;
            int count = (int)(exceptionSize / 12); // RUNTIME_FUNCTION = 3 x DWORD
            for (int i = 0; i < count; i++)
            {
                ulong entryVa = tableVa + (ulong)(i * 12);
                long beginRva = ReadU32(entryVa);
                long endRva = ReadU32(entryVa + 4);
                if (beginRva < 0 || endRva <= beginRva)
                {
                    continue;
                }

                _runtimeFunctions.Add(new RuntimeFunction
                {
                    Begin = ImageBase + (ulong)beginRva,
                    End = ImageBase + (ulong)endRva,
                });
            }
        }

        private static string ReadSectionName(byte[] file, int entry)
        {
            int length = 0;
            while (length < 8 && file[entry + length] != 0)
            {
                length++;
            }
            return System.Text.Encoding.ASCII.GetString(file, entry, length);
        }

        public Section SectionForVa(ulong va)
        {
            foreach (Section section in _sections)
            {
                if (va >= section.VirtualStart && va < section.VirtualEnd)
                {
                    return section;
                }
            }
            return null;
        }

        public bool ContainsVa(ulong va) => SectionForVa(va) != null;

        public bool IsExecutable(ulong va)
        {
            Section section = SectionForVa(va);
            return section != null && section.Executable;
        }

        // Returns -1 for unmapped or uninitialized (bss) bytes.
        public int ReadByte(ulong va)
        {
            Section section = SectionForVa(va);
            if (section == null)
            {
                return -1;
            }
            ulong offset = va - section.VirtualStart;
            if (offset >= (ulong)section.Raw.Length)
            {
                return -1;
            }
            return section.Raw[offset];
        }

        public byte[] ReadBytes(ulong va, int length)
        {
            byte[] buffer = new byte[length];
            for (int i = 0; i < length; i++)
            {
                int value = ReadByte(va + (ulong)i);
                buffer[i] = value < 0 ? (byte)0 : (byte)value;
            }
            return buffer;
        }

        private long ReadU32(ulong va)
        {
            int b0 = ReadByte(va);
            int b1 = ReadByte(va + 1);
            int b2 = ReadByte(va + 2);
            int b3 = ReadByte(va + 3);
            if ((b0 | b1 | b2 | b3) < 0)
            {
                return -1;
            }
            return b0 | (b1 << 8) | (b2 << 16) | ((long)b3 << 24);
        }
    }
}
