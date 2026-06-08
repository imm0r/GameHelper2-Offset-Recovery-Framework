using System;
using System.IO;
using PoEformance;

namespace PoEformance.Tests
{
    // Builds a minimal but valid PE32+ in memory: one .text (code), one .rdata
    // (strings + a qword), one .pdata (RUNTIME_FUNCTION table). This lets the whole
    // pipeline be exercised deterministically without the real game binary.
    //
    // .text layout (RVA 0x1000):
    //   A @ 0x1000: MOV RAX,[rip->QwordData]; CALL B; CALL C; RET   (A,B in .pdata)
    //   B @ 0x1020: RET
    //   C @ 0x1030: RET                                              (NOT in .pdata -> CALL sweep)
    internal static class TestPe
    {
        public const ulong ImageBase = 0x140000000UL;
        public const uint TextRva = 0x1000;
        public const uint RdataRva = 0x2000;
        public const uint PdataRva = 0x3000;

        public const ulong FuncA = ImageBase + TextRva + 0x00;        // 0x140001000
        public const ulong CallBSite = ImageBase + TextRva + 0x07;    // 0x140001007
        public const ulong FuncB = ImageBase + TextRva + 0x20;        // 0x140001020 (in .pdata)
        public const ulong FuncC = ImageBase + TextRva + 0x30;        // 0x140001030 (synthetic)
        public const ulong QwordData = ImageBase + RdataRva + 0x00;   // 0x140002000
        public const ulong ModsString = ImageBase + RdataRva + 0x10;  // 0x140002010
        public const ulong HelloString = ImageBase + RdataRva + 0x20; // 0x140002020

        public static byte[] Build()
        {
            byte[] file = new byte[0x500];

            file[0] = (byte)'M';
            file[1] = (byte)'Z';
            WriteU32(file, 0x3C, 0x80); // e_lfanew

            int pe = 0x80;
            file[pe] = (byte)'P';
            file[pe + 1] = (byte)'E';

            int coff = pe + 4;
            WriteU16(file, coff + 0, 0x8664); // Machine x64
            WriteU16(file, coff + 2, 3);       // NumberOfSections
            WriteU16(file, coff + 16, 0xF0);   // SizeOfOptionalHeader

            int opt = coff + 20;
            WriteU16(file, opt + 0, 0x20B);          // PE32+ magic
            WriteU32(file, opt + 16, TextRva);       // AddressOfEntryPoint
            WriteU64(file, opt + 24, ImageBase);     // ImageBase
            WriteU32(file, opt + 108, 16);           // NumberOfRvaAndSizes
            WriteU32(file, opt + 112 + 3 * 8, PdataRva); // Exception directory RVA
            WriteU32(file, opt + 112 + 3 * 8 + 4, 0x18); // Exception directory size (2 entries)

            int sec = opt + 0xF0;
            int textRaw = 0x400, rdataRaw = 0x440, pdataRaw = 0x480;
            WriteSection(file, sec + 0 * 40, ".text", TextRva, 0x40, 0x40, textRaw, 0x60000000); // exec+read
            WriteSection(file, sec + 1 * 40, ".rdata", RdataRva, 0x40, 0x40, rdataRaw, 0x40000000); // read
            WriteSection(file, sec + 2 * 40, ".pdata", PdataRva, 0x18, 0x18, pdataRaw, 0x40000000); // read

            byte[] text =
            {
                0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00, // MOV RAX,[rip+0xFF9] -> 0x140002000
                0xE8, 0x14, 0x00, 0x00, 0x00,             // CALL +0x14 -> B (0x140001020)
                0xE8, 0x1F, 0x00, 0x00, 0x00,             // CALL +0x1F -> C (0x140001030)
                0xC3,                                     // RET
            };
            Array.Copy(text, 0, file, textRaw, text.Length);
            for (int i = text.Length; i < 0x40; i++)
            {
                file[textRaw + i] = 0xCC; // padding
            }
            file[textRaw + 0x20] = 0xC3; // B: RET
            file[textRaw + 0x30] = 0xC3; // C: RET

            PutAsciiz(file, rdataRaw + 0x10, "Mods.dat");
            PutAsciiz(file, rdataRaw + 0x20, "Hello");

            // .pdata: RUNTIME_FUNCTION { BeginRva, EndRva, UnwindRva } for A and B.
            WriteU32(file, pdataRaw + 0, TextRva + 0x00);
            WriteU32(file, pdataRaw + 4, TextRva + 0x12);
            WriteU32(file, pdataRaw + 8, 0);
            WriteU32(file, pdataRaw + 12, TextRva + 0x20);
            WriteU32(file, pdataRaw + 16, TextRva + 0x21);
            WriteU32(file, pdataRaw + 20, 0);

            return file;
        }

        public static PeImage LoadImage() => LoadBytes(Build());

        public static PeImage LoadBytes(byte[] file)
        {
            string path = Path.Combine(Path.GetTempPath(), "offsetrec_" + Guid.NewGuid().ToString("n") + ".bin");
            File.WriteAllBytes(path, file);
            try
            {
                return PeImage.Load(path);
            }
            finally
            {
                File.Delete(path);
            }
        }

        private static void WriteSection(byte[] file, int off, string name, uint rva, uint vsize, uint rawSize,
            int rawPtr, uint chars)
        {
            byte[] n = System.Text.Encoding.ASCII.GetBytes(name);
            Array.Copy(n, 0, file, off, n.Length);
            WriteU32(file, off + 8, vsize);
            WriteU32(file, off + 12, rva);
            WriteU32(file, off + 16, rawSize);
            WriteU32(file, off + 20, (uint)rawPtr);
            WriteU32(file, off + 36, chars);
        }

        private static void PutAsciiz(byte[] file, int off, string s)
        {
            byte[] b = System.Text.Encoding.ASCII.GetBytes(s);
            Array.Copy(b, 0, file, off, b.Length);
            file[off + b.Length] = 0;
        }

        private static void WriteU16(byte[] f, int o, int v)
        {
            f[o] = (byte)v;
            f[o + 1] = (byte)(v >> 8);
        }

        private static void WriteU32(byte[] f, int o, uint v)
        {
            f[o] = (byte)v;
            f[o + 1] = (byte)(v >> 8);
            f[o + 2] = (byte)(v >> 16);
            f[o + 3] = (byte)(v >> 24);
        }

        private static void WriteU64(byte[] f, int o, ulong v)
        {
            for (int i = 0; i < 8; i++)
            {
                f[o + i] = (byte)(v >> (8 * i));
            }
        }
    }
}
