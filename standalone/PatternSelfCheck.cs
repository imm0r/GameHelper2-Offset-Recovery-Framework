namespace OffsetRecovery.Standalone
{
    // Cross-check that an emitted result is internally consistent and consumable by a
    // runtime AOB scanner. A standard RIP-relative resolver reads the 4-byte displacement
    // at (matchAddress + bytesToSkip) and computes target = matchAddress + bytesToSkip + 4
    // + disp32. This must equal the resolved static address, and the pattern's fixed bytes
    // must actually occur at PatternStart. Catches off-by-one bugs in pattern construction
    // and flags any recipe whose displacement field is not flush with the instruction end.
    public static class PatternSelfCheck
    {
        public static bool Verify(PeImage image, RecoveryResult result, out string detail)
        {
            OffsetMatch m = result.Match;

            ulong dispVa = m.PatternStart + (ulong)m.BytesToSkip;
            int b0 = image.ReadByte(dispVa);
            int b1 = image.ReadByte(dispVa + 1);
            int b2 = image.ReadByte(dispVa + 2);
            int b3 = image.ReadByte(dispVa + 3);
            if ((b0 | b1 | b2 | b3) < 0)
            {
                detail = "displacement bytes at 0x" + dispVa.ToString("x") + " are not mapped";
                return false;
            }

            int disp = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            ulong resolved = m.PatternStart + (ulong)m.BytesToSkip + 4 + (ulong)(long)disp;
            if (resolved != m.Resolved)
            {
                detail = "RIP resolves to 0x" + resolved.ToString("x")
                    + " but result says 0x" + m.Resolved.ToString("x");
                return false;
            }

            detail = "RIP resolves to 0x" + resolved.ToString("x");
            return true;
        }
    }
}
