using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using BinaryObjectScanner.Interfaces;
using SabreTools.Data.Models.ISO9660;
using SabreTools.IO;
using SabreTools.IO.Extensions;
using SabreTools.IO.Matching;
using SabreTools.Serialization.Wrappers;
using static SabreTools.Data.Models.SecuROM.Constants;

namespace BinaryObjectScanner.Protection
{
    // TODO: Investigate SecuROM for Macintosh
    // TODO: Think of a way to detect dfe
    public class SecuROM : IDiskImageCheck<ISO9660>, IExecutableCheck<PortableExecutable>, IPathCheck
    {
        /// <summary>
        /// Matches hash of the Release Control-encrypted executable to known hashes
        /// </summary>
        /// <remarks>Allegedly, some version of Runaway: A Twist of Fate has RC</remarks>
        private static readonly Dictionary<string, string> MatroschkaHashDictionary = new()
        {
            {"C6DFF6B08EE126893840E107FD4EC9F6", "Alice - Madness Returns (USA)+(Europe)"},
            {"D7703D32B72185358D58448B235BD55E", "Arcania - Gothic 4 (Australia)"}, // International version (English, French, Italian, German, Spanish)
            // Arcania - Gothic 4 - Polish(/Hungarian?) - known to most likely exist. Likely matches support site exe.
            {"83CD6225899C08422F860095962287A5", "Arcania - Gothic 4 (Russia)"},
            // Arcania - Gothic 4 - Chinese - known to most likely exist. Likely matches support site exe.
            {"FAF6DD75DDB335101CB77A714793DC28", "Batman - Arkham City - Game of the Year Edition (UK)"},
            {"77999579EE4378BDFAC9438CC9CDB44E", "Batman - Arkham City (USA)+(Europe)"},
            {"73114CF3DEEDD0FA2BF52ACB70B048BC", "Battlefield - Bad Company 2 (GFWM)"},
            {"56C23D930F885BA5BF026FEABFC31856", "Battlefield 3 (USA)+(Europe, Asia)"},
            {"631C0ACE596722488E3393BD1AFCE731", "Battlefield 3 (Russia)"},
            {"6E481CDEBDB30B8889340CEC3300C931", "Battlefield 3 (UK)"},
            {"C5AB3931A3CBB0141CC5A4638C391F4F", "BioShock 2 (Argentina)+(Europe, Australia)+(Europe)+(Europe) (Alt)+(Netherlands)+(USA) - Multiplayer executable"},
            {"73DB35419A651CB69E78A641BBC88A4C", "BioShock 2 (Argentina)+(Europe, Australia)+(Europe)+(Europe) (Alt)+(Netherlands)+(USA) - Singleplayer executable"},
            {"E5D63D369023A1D1074E7B13952FA0F2", "BioShock 2 (Russia) - Multiplayer executable"},
            {"C39F3BCB74EA8E1215D39AC308F64229", "BioShock 2 (Russia) - Singleplayer executable"},
            {"3C340B2D4DA25039C136FEE1DC2DDE17", "Borderlands (USA)+(Europe) (En,Fr,De,Es,It)"},
            {"D35122E0E3F7B35C98BEFD706C260F83", "Crysis Warhead (Europe)+(Russia)+(USA)+(USA) (Alt)"},
            {"D9254D3353AB229806A806FCFCEABDBD", "Crysis Warhead (Japan)"},
            {"D69798C9198A6DB6A265833B350AC544", "Crysis Warhead (Turkey)"},
            {"9F574D56F1A4D7847C6A258DC2AF61A5", "Crysis Wars (Europe)+(Japan)+(Russia)+(Turkey)+(USA)+(USA) (Rerelease)"},
            {"C200ABC342A56829A5356AA0BEA5F2DF", "Dead Space 2 (Europe)+(Russia)+(USA)"},
            {"81B3415AF21C8691A1CD55A422BA64D5", "Disney TRON - Evolution (Europe) (En,Fr,De,Es,It,Nl)"},
            {"DF9609EDE95A1F89F7A39A08778CC3B8", "Disney Tron - Evolution (Europe) (Pl,Cs)"},
            {"B8698C7C05D7F9E049DC038B9868FCF7", "Disney TRON - Evolution (Russia) (En,Ru)"},
            {"0D5800F94643633CD3F025CFFD968DF2", "Dragon Age II (Europe)+(USA) - PC executable"},
            {"3F1AFA4783F9001AACF0379A2A432A13", "Dragon Age II (Europe)+(USA) - Mac executable"},
            {"530A3EB454570EEE5519ABE6BAE0187C", "Far Cry 2 (Europe)+(USA) (En,Fr,De,Es,It)"},
            {"4B3B130A70F3711BFA8AF06195FE4250", "FIFA 12 (Europe)"},
            {"F43F777696B0FAD3A331298C48104B31", "FIFA 13 (Europe)"},
            {"1DF0E096068839C12E4B353AC50E41FA", "Grand Theft Auto - Episodes from Liberty City (Russia)"},
            {"F3ADC6D08BEC42FB988F2F62B5C731FA", "Grand Theft Auto - Episodes from Liberty City (USA)"},
            {"5B90D42A650A8F08095984AEE3D961B9", "Grand Theft Auto IV (Europe, Asia)+(Europe)+(Latin America)+(USA) (Rev 1)"},
            {"4510F0BDD58D30D072952E225E294F9B", "Grand Theft Auto IV (USA)"},
            {"2AC9616A7FE46D142F653D798EAA07FD", "Harry Potter and the Deathly Hallows Part 2 (GFWM)"},
            {"AE144755FB12062780E4E4CCD29B5296", "Kingdoms of Amalur - Reckoning (Germany)"},
            {"6E4AB6416D91F85954150BC50D02688E", "Kingdoms of Amalur - Reckoning (USA) (En,Fr,Es,It,Nl)"},
            {"935103B1600F1C743AF892A0DD761913", "Mass Effect 2 (GFWM)"},
            {"EEB2AE163AEEF6BE54C5A9BDD38C600E", "Mass Effect 3 (Europe, Australia)+(USA)"},
            {"2D08B73217B722A4F9E01523F07E118E", "Mass Effect 3 (UK)"},
            {"4EA3CE0670DECD0A74FA312714C22025", "Need for Speed - The Run (Europe)"},
            {"88AB0D4A4EE7867F740AD063400FCDB5", "Need for Speed - The Run (Russia)"},
            {"EAD8E224D0F44706BA92BD9B27FEBA7D", "Need for Speed - The Run (USA)"},
            {"316FF217BD129F9EEBD05A321A8FBE60", "Syndicate (USA)+(Europe) (En,Fr,De,Es,It,Ru)"},
        };

        /// <summary>
        /// If hash isn't currently known, check size and pathname of the encrypted executable
        /// to determine if alt or entirely missing
        /// </summary>
        private static readonly Dictionary<uint, string> MatroschkaSizeFilenameDictionary = new()
        {
            {4646091, "hp8.aec"},
            {5124592, "output\\LaunchGTAIV.aec"},
            {5445032, "output\\Crysis.aec"},
            {5531004, "output\\FarCry2.aec"},
            {6716108, "LaunchEFLC.aec"},
            {6728396, "./Bioshock2Launcher.aec"},
            {6732492, "./BioShock2Launcher.aec"},
            {7150283, "GridGameLauncher.aec"},
            {7154379, "GridGameLauncher.aec"},
            {8705763, "temp0.aec"},
            {12137051, "dragonage2.aec"},
            {12896904, "output\\crysis.aec"},
            {12917384, "output\\crysis.aec"},
            {12925576, "output\\crysis.aec"},
            {16415836, "output\\MassEffect2.aec"},
            {17199339, "AliceMadnessReturns.aec"},
            {22357747, "MassEffect3.aec"},
            {23069931, "fifa.aec"},
            {25410419, "Arcania.aec"},
            {25823091, "Arcania.aec"},
            {27564780, "output\\BFBC2Game.aec"},
            {30470419, "temp0.aec"},
            {32920811, "temp0.aec"},
            {35317996, "output\\ShippingPC-WillowGame-SecuROM.aec"},
            {35610875, "temp0.aec"},
            {37988075, "temp0.aec"},
            {43612419, "BatmanAC.aec"},
            {45211355, "BatmanAC.aec"},
            {48093043, "deadspace_f.aec"},
        };

        /// <inheritdoc/>
        public string? CheckDiskImage(string file, ISO9660 diskImage, bool includeDebug)
        {

            if (diskImage.VolumeDescriptorSet.Length == 0)
                return null;
            if (diskImage.VolumeDescriptorSet[0] is not PrimaryVolumeDescriptor pvd)
                return null;

            // Application Use is too inconsistent to include or exclude

            // There needs to be noteworthy data in the reserved 653 bytes
            if (!FileType.ISO9660.NoteworthyReserved653Bytes(pvd))
                return null;

            var applicationUse = pvd.ApplicationUse;
            var reserved653Bytes = pvd.Reserved653Bytes;

            #region Read Application Use

            var offset = 0;

            // Either there's nothing of note, or it's empty other than a 4-byte value at the start.
            if (FileType.ISO9660.NoteworthyApplicationUse(pvd))
            {
                uint appUseUint = applicationUse.ReadUInt32LittleEndian(ref offset);
                var appUseZeroBytes = applicationUse.ReadBytes(ref offset, 508);

                if (appUseUint == 0 || !Array.TrueForAll(appUseZeroBytes, b => b == 0x00))
                    return null;
            }

            #endregion

            #region Read Reserved 653 Bytes

            offset = 0;

            var reservedZeroBytesOne = reserved653Bytes.ReadBytes(ref offset, 489);
            uint reservedHundredValue = reserved653Bytes.ReadUInt32LittleEndian(ref offset);
            var reserveDataBytesOne = reserved653Bytes.ReadBytes(ref offset, 80);
            var reservedZeroBytesTwo = reserved653Bytes.ReadBytes(ref offset, 12);
            uint reservedUintOne = reserved653Bytes.ReadUInt32LittleEndian(ref offset);
            uint reservedUintTwoLow = reserved653Bytes.ReadUInt32LittleEndian(ref offset); // Low value
            var reservedZeroBytesThree = reserved653Bytes.ReadBytes(ref offset, 4);
            uint reservedUintThree = reserved653Bytes.ReadUInt32LittleEndian(ref offset);
            var reservedZeroBytesFour = reserved653Bytes.ReadBytes(ref offset, 12);
            uint reservedUintFour = reserved653Bytes.ReadUInt32LittleEndian(ref offset);
            uint reservedOneValue = reserved653Bytes.ReadUInt32LittleEndian(ref offset);
            var reservedZeroBytesFive = reserved653Bytes.ReadBytes(ref offset, 4);
            var reservedDataBytesTwo = reserved653Bytes.ReadBytes(ref offset, 12);
            byte reservedLowByteValueOne = reserved653Bytes.ReadByteValue(ref offset);
            byte reservedLowByteValueTwo = reserved653Bytes.ReadByteValue(ref offset);
            byte reservedLowByteValueThree = reserved653Bytes.ReadByteValue(ref offset);
            byte reservedLowByteValueFour = reserved653Bytes.ReadByteValue(ref offset);
            var reservedDataBytesThree = reserved653Bytes.ReadBytes(ref offset, 12);

            #endregion

            // True for all discs
            if (!Array.TrueForAll(reservedZeroBytesOne, b => b == 0x00)
                || !Array.TrueForAll(reservedZeroBytesTwo, b => b == 0x00)
                || !Array.TrueForAll(reservedZeroBytesThree, b => b == 0x00)
                || !Array.TrueForAll(reservedZeroBytesFour, b => b == 0x00)
                || !Array.TrueForAll(reservedZeroBytesFive, b => b == 0x00))
            {
                return null;
            }

            #region Early SecuROM Checks

            // This duplicates a lot of code. This region is like this because it's still possible to detect early vers,
            // but it should be easy to remove this section if it turns out this leads to conflicts or false positives
            if (Array.TrueForAll(reserveDataBytesOne, b => b == 0x00)
                && Array.TrueForAll(reservedDataBytesTwo, b => b == 0x00)
                && reservedHundredValue == 0 && reservedOneValue == 0
                && reservedUintOne == 0 && reservedUintTwoLow == 0 && reservedUintThree == 0 && reservedUintFour == 0
                && reservedLowByteValueOne == 0 && reservedLowByteValueTwo == 0 && reservedLowByteValueThree == 0)
            {
                if (FileType.ISO9660.IsPureData(reservedDataBytesThree))
                {
                    if (reservedLowByteValueFour == 0)
                        return "SecuROM 3.x-4.6x";
                    else if (reservedLowByteValueFour < 0x20)
                        return "SecuROM 4.7x-4.8x";
                    else
                        return null;
                }

                offset = 0;
                var earlyFirstFourBytes = reservedDataBytesThree.ReadBytes(ref offset, 4);
                var earlyLastEightBytes = reservedDataBytesThree.ReadBytes(ref offset, 8);

                if (Array.TrueForAll(earlyFirstFourBytes, b => b == 0x00) && FileType.ISO9660.IsPureData(earlyLastEightBytes))
                    return "SecuROM 2.x-3.x";
            }

            #endregion

            // If this uint32 is 100, the next 80 bytes should be data. Otherwise, both should only ever be zero.

            switch (reservedHundredValue)
            {
                case 0:
                    if (!Array.TrueForAll(reserveDataBytesOne, b => b == 0x00))
                        return null;
                    break;
                case 100:
                    if (!FileType.ISO9660.IsPureData(reserveDataBytesOne))
                        return null;
                    break;
                default:
                    return null;
            }

            //If you go back to early 4.0 CDs, only the above can be guaranteed to pass. CDs can already be identified via normal
            //dumping, though, and  (as well as most later CDs) should always pass these remaining checks.
            if (reservedUintOne < 0xFFFF || reservedUintTwoLow > 0xFFFF || reservedUintThree < 0xFFFF || reservedUintFour < 0xFFFF)
                return null;

            if (reservedOneValue != 1)
                return null;

            if (reservedLowByteValueOne > 0x20 || reservedLowByteValueTwo > 0x20 || reservedLowByteValueThree > 0x20 ||
                reservedLowByteValueFour > 0x20)
                return null;

            // TODO: RID 127715 fails this because the first 8 bytes of reservedDataBytesTwo happen to be "afsCafsC"
            if (!FileType.ISO9660.IsPureData(reservedDataBytesTwo)
                || !FileType.ISO9660.IsPureData(reservedDataBytesThree))
                return null;

            return "SecuROM 4.8x+";
        }

        /// <inheritdoc/>
        public string? CheckExecutable(string file, PortableExecutable exe, bool includeDebug)
        {
            // Check if executable is a SecuROM PA module
            var paModule = CheckProductActivation(exe);
            if (paModule != null)
                return paModule;

            // Check if executable contains a SecuROM Matroschka Package
            var package = exe.MatroschkaPackage;
            if (package != null)
            {
                var packageType = CheckMatroschkaPackage(package, includeDebug);
                if (packageType != null)
                    return packageType;
            }

            // Alf.dll
            string? name = exe.ProductName;
            if (name.OptionalEquals("DFA Unlock Dll"))
                return $"SecuROM DFA Unlock v{exe.GetInternalVersion()}";

            if (name.OptionalEquals("Release Control Unlock Dll"))
                return $"SecuROM Release Control Unlock v{exe.GetInternalVersion()}";

            // Dfa.dll and ca.dll. The former seems to become the latter later on.
            name = exe.FileDescription;
            if (name.OptionalEquals("SecuROM Data File Activation Library"))
                return $"SecuROM Data File Activation v{exe.GetInternalVersion()}";

            // Copyright is only checked because "Content Activation Library" seems broad on its own.
            if (name.OptionalEquals("Content Activation Library") && exe.LegalCopyright.OptionalContains("Sony DADC Austria AG"))
                return $"SecuROM Content Activation v{exe.GetInternalVersion()}";

            if (exe.ContainsSection(".dsstext", exact: true))
            {
                var sectionData = exe.GetFirstSectionData(".dsstext", true);
                var moduloString = GetModulo(sectionData, 0, file);
                if (moduloString != null)
                    return $"SecuROM 8.03.03+{CheckModulo(moduloString, includeDebug)}";
                
                return $"SecuROM 8.03.03+";
            }

            // Get the .securom section, if it exists
            if (exe.ContainsSection(".securom", exact: true))
            {
                var sectionData = exe.GetFirstSectionData(".securom", true);

                // While there are two early outliers at 7.21 and 7.24 (d2d GRAW and d2d HOMMV), these are huge outliers,
                // and every single other known PA-capable executable is 7.27 or later. In order to avoid both flooding
                // user's logs and lots of unnecessary investigation, this should only be checked if version is 7.27 or
                // higher, or if debug mode is enabled for testing purposes.
                var v7Version = GetV7Version(exe);
                if (includeDebug || (decimal.TryParse(v7Version.Substring(0, 4), out decimal v7Decimal) && v7Decimal >= (decimal)7.27))
                {
                    var moduloString = GetModulo(sectionData, 0, file);
                    if (moduloString != null)
                    {
                        return $"SecuROM {v7Version}{CheckModulo(moduloString, includeDebug)}";
                    }
                }
                
                return $"SecuROM {v7Version}";
            }

            // Get the .sll section, if it exists
            if (exe.ContainsSection(".sll", exact: true))
                return $"SecuROM SLL Protected (for SecuROM v8.x)";

            // Search after the last section
            string? v4Version = GetV4Version(exe);
            if (v4Version != null)
                return $"SecuROM {v4Version}";

            // TODO: Investigate if this can be found by aligning to section containing entry point

            // Get the sections 5+, if they exist (example names: .fmqyrx, .vcltz, .iywiak)
            var sections = exe.SectionTable ?? [];
            for (int i = 4; i < sections.Length; i++)
            {
                var nthSection = sections[i];
                if (nthSection == null)
                    continue;

                string nthSectionName = Encoding.ASCII.GetString(nthSection.Name ?? []).TrimEnd('\0');
                if (nthSectionName != ".idata" && nthSectionName != ".rsrc")
                {
                    var nthSectionData = exe.GetFirstSectionData(nthSectionName);
                    if (nthSectionData == null)
                        continue;

                    var matchers = new List<ContentMatchSet>
                    {
                        // (char)0xCA + (char)0xDD + (char)0xDD + (char)0xAC + (char)0x03
                        new(new byte?[] { 0xCA, 0xDD, 0xDD, 0xAC, 0x03 }, GetV5Version, "SecuROM"),
                    };

                    var match = MatchUtil.GetFirstMatch(file, nthSectionData, matchers, includeDebug);
                    if (!string.IsNullOrEmpty(match))
                        return match;
                }
            }

            // Get the .rdata section strings, if they exist
            var strs = exe.GetFirstSectionStrings(".rdata");
            if (strs != null)
            {
                // Both have the identifier found within `.rdata` but the version is within `.data`
                // TODO: need help with what functions i can use to perform the check in .data
                var sectionData = exe.GetFirstSectionData(".data", true) ?? exe.GetFirstSectionData(".DATA", true);

                if (strs.Exists(s => s.Contains("/secuexp")) || (strs.Exists(s => s.Contains("SecuExp.exe"))))
                {
                    var matchers = new List<ContentMatchSet>
                    {
                        new(Encoding.ASCII.GetBytes("1d47b0b0981cc4fc00a6eccc0244a3"), WhiteLabelModuloHelper, ""),
                    };

                    var match = MatchUtil.GetFirstMatch(file, sectionData, matchers, includeDebug);
                     
                    if (!string.IsNullOrEmpty(match))
                        return $"SecuROM {GetV8WhiteLabelVersion(exe)} (White Label){CheckModulo(match!, includeDebug)}";

                    return $"SecuROM {GetV8WhiteLabelVersion(exe)} (White Label)";
                }
            }

            // Get the .cms_d and .cms_t sections, if they exist -- TODO: Confirm if both are needed or either/or is fine
            if (exe.ContainsSection(".cmd_d", true))
                return $"SecuROM 1-3";
            if (exe.ContainsSection(".cms_t", true))
                return $"SecuROM 1-3";

            return null;
        }

        /// <inheritdoc/>
        public List<string> CheckDirectoryPath(string path, List<string>? files)
        {
            var matchers = new List<PathMatchSet>
            {
                // TODO: Verify if these are OR or AND
                new(new FilePathMatch("CMS16.DLL"), "SecuROM"),
                new(new FilePathMatch("CMS_95.DLL"), "SecuROM"),
                new(new FilePathMatch("CMS_NT.DLL"), "SecuROM"),
                new(new FilePathMatch("CMS32_95.DLL"), "SecuROM"),
                new(new FilePathMatch("CMS32_NT.DLL"), "SecuROM"),

                // TODO: Verify if these are OR or AND
                new(new FilePathMatch("SINTF32.DLL"), "SecuROM New"),
                new(new FilePathMatch("SINTF16.DLL"), "SecuROM New"),
                new(new FilePathMatch("SINTFNT.DLL"), "SecuROM New"),

                // TODO: Find more samples of this for different versions
                new(
                [
                    new FilePathMatch("securom_v7_01.bak"),
                    new FilePathMatch("securom_v7_01.dat"),
                    new FilePathMatch("securom_v7_01.tmp"),
                ], "SecuROM 7.01"),
            };

            return MatchUtil.GetAllMatches(files, matchers, any: true);
        }

        /// <inheritdoc/>
        public string? CheckFilePath(string path)
        {
            var matchers = new List<PathMatchSet>
            {
                new(new FilePathMatch("CMS16.DLL"), "SecuROM"),
                new(new FilePathMatch("CMS_95.DLL"), "SecuROM"),
                new(new FilePathMatch("CMS_NT.DLL"), "SecuROM"),
                new(new FilePathMatch("CMS32_95.DLL"), "SecuROM"),
                new(new FilePathMatch("CMS32_NT.DLL"), "SecuROM"),

                new(new FilePathMatch("SINTF32.DLL"), "SecuROM New"),
                new(new FilePathMatch("SINTF16.DLL"), "SecuROM New"),
                new(new FilePathMatch("SINTFNT.DLL"), "SecuROM New"),

                new(new FilePathMatch("securom_v7_01.bak"), "SecuROM 7.01"),
                new(new FilePathMatch("securom_v7_01.dat"), "SecuROM 7.01"),
                new(new FilePathMatch("securom_v7_01.tmp"), "SecuROM 7.01"),
            };

            return MatchUtil.GetFirstMatch(path, matchers, any: true);
        }

        /// <summary>
        /// Try to get the SecuROM v4 version from the overlay, if possible
        /// </summary>
        /// <returns>The version on success, null otherwise</returns>
        private static string? GetV4Version(PortableExecutable exe)
        {
            // Cache the overlay data for easier access
            var overlayData = exe.OverlayData;
            if (overlayData == null || overlayData.Length < 20)
                return null;

            // Search for the "AddD" string in the overlay
            bool found = false;
            int index = 0;
            for (; index < 0x20 && index + 4 < overlayData.Length; index++)
            {
                int temp = index;
                byte[] overlaySample = overlayData.ReadBytes(ref temp, 0x04);
                if (overlaySample.EqualsExactly(AddDMagicBytes))
                {
                    found = true;
                    break;
                }
            }

            // If the string wasn't found in the first 0x20 bytes
            if (!found)
                return null;

            // Deserialize the AddD header
            var reader = new SabreTools.Serialization.Readers.SecuROMAddD();
            var addD = reader.Deserialize(overlayData, index);
            if (addD == null)
                return null;

            // All samples have had 3 entries -- Revisit if needed
            if (addD.EntryCount != 3)
                return null;

            // Format the version
            string version = $"{addD.Version}.{addD.Build}";
            if (!char.IsNumber(version[0]))
                return "(very old, v3 or less)";

            return version;
        }

        /// <summary>
        /// Try to get the SecuROM v5 version from section data, if possible
        /// </summary>
        /// <returns>The version on success, null otherwise</returns>
        private static string? GetV5Version(string file, byte[]? fileContent, List<int> positions)
        {
            // If we have no content
            if (fileContent == null)
                return null;

            int index = positions[0] + 8; // Begin reading after "ÊÝÝ¬"
            byte major = (byte)(fileContent[index] & 0x0F);
            index += 2;

            byte[] minor = new byte[2];
            minor[0] = (byte)(fileContent[index] ^ 36);
            index++;
            minor[1] = (byte)(fileContent[index] ^ 28);
            index += 2;

            byte[] patch = new byte[2];
            patch[0] = (byte)(fileContent[index] ^ 42);
            index++;
            patch[1] = (byte)(fileContent[index] ^ 8);
            index += 2;

            byte[] revision = new byte[4];
            revision[0] = (byte)(fileContent[index] ^ 16);
            index++;
            revision[1] = (byte)(fileContent[index] ^ 116);
            index++;
            revision[2] = (byte)(fileContent[index] ^ 34);
            index++;
            revision[3] = (byte)(fileContent[index] ^ 22);

            if (major == 0 || major > 9)
                return string.Empty;

            return $"{major}.{minor[0]}{minor[1]}.{patch[0]}{patch[1]}.{revision[0]}{revision[1]}{revision[2]}{revision[3]}";
        }

        /// <summary>
        /// Try to get the SecuROM v7 version from MS-DOS stub data, if possible
        /// </summary>
        /// <returns>The version on success, null otherwise</returns>
        private static string GetV7Version(PortableExecutable exe)
        {
            // If SecuROM is stripped, the MS-DOS stub might be shorter.
            // We then know that SecuROM -was- there, but we don't know what exact version.
            if (exe.StubExecutableData == null)
                return "7 remnants";

            //SecuROM 7 new and 8 -- 64 bytes for DOS stub, 236 bytes in total
            int index = 172;
            if (exe.StubExecutableData.Length >= 176 && exe.StubExecutableData[index + 3] == 0x5C)
            {
                int major = exe.StubExecutableData[index + 0] ^ 0xEA;
                int minor = exe.StubExecutableData[index + 1] ^ 0x2C;
                int patch = exe.StubExecutableData[index + 2] ^ 0x08;

                return $"{major}.{minor:00}.{patch:0000}";
            }

            // SecuROM 7 old -- 64 bytes for DOS stub, 122 bytes in total
            index = 58;
            if (exe.StubExecutableData.Length >= 62)
            {
                int minor = exe.StubExecutableData[index + 0] ^ 0x10;
                int patch = exe.StubExecutableData[index + 1] ^ 0x10;

                //return "7.01-7.10"
                return $"7.{minor:00}.{patch:0000}";
            }

            // If SecuROM is stripped, the MS-DOS stub might be shorter.
            // We then know that SecuROM -was- there, but we don't know what exact version.
            return "7 remnants";
        }

        /// <summary>
        /// Try to get the SecuROM v8 (White Label) version from the .data section, if possible
        /// </summary>
        /// <returns>The version on success, null otherwise</returns>
        private static string GetV8WhiteLabelVersion(PortableExecutable exe)
        {
            // Get the .data/DATA section, if it exists
            var dataSectionRaw = exe.GetFirstSectionData(".data") ?? exe.GetFirstSectionData("DATA");
            if (dataSectionRaw == null)
                return "8";

            // Search .data for the version indicator
            var matcher = new ContentMatch(
            [
                0x29, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null,
                0x82, 0xD8, 0x0C, 0xAC
            ]);

            int position = matcher.Match(dataSectionRaw);

            // If we can't find the string, we default to generic
            if (position < 0)
                return "8";

            int major = dataSectionRaw[position + 0xAC + 0] ^ 0xCA;
            int minor = dataSectionRaw[position + 0xAC + 1] ^ 0x39;
            int patch = dataSectionRaw[position + 0xAC + 2] ^ 0x51;

            return $"{major}.{minor:00}.{patch:0000}";
        }

        /// <summary>
        /// Helper method to run checks on a SecuROM Matroschka Package
        /// </summary>
        private static string? CheckMatroschkaPackage(SecuROMMatroschkaPackage package, bool includeDebug)
        {
            // Check for all 0x00 required, as at least one known non-RC matroschka has the field, just empty.
            if (package.KeyHexString == null || package.KeyHexString.Trim('\0').Length == 0)
                return "SecuROM Matroschka Package";

            if (package.Entries == null || package.Entries.Length == 0)
                return "SecuROM Matroschka Package - No Entries? - Please report to us on GitHub";

            // The second entry in a Release Control matroschka package is always the encrypted executable
            var entry = package.Entries[1];

            if (entry.MD5 == null || entry.MD5.Length == 0)
                return "SecuROM Matroschka Package - No MD5? - Please report to us on GitHub";

            string md5String = BitConverter.ToString(entry.MD5!);
            md5String = md5String.ToUpperInvariant().Replace("-", string.Empty);

            // TODO: Not used yet, but will be in the future
            var fileData = package.ReadFileData(entry, includeDebug);

            // Check if encrypted executable is known via hash
            if (MatroschkaHashDictionary.TryGetValue(md5String, out var gameName))
                return $"SecuROM Release Control -  {gameName}";

            // If not known, check if encrypted executable is likely an alt signing of a known executable
            // Filetime could be checked here, but if it was signed at a different time, the time will vary anyways
            var readPath = entry.Path;
            if (readPath == null || readPath.Length == 0)
                return $"SecuROM Release Control - Unknown executable {md5String},{entry.Size} - Please report to us on GitHub!";

            var readPathName = readPath.TrimEnd('\0');
            if (MatroschkaSizeFilenameDictionary.TryGetValue(entry.Size, out var pathName) && pathName == readPathName)
                return $"SecuROM Release Control - Unknown possible alt executable of size {entry.Size} - Please report to us on GitHub";

            return $"SecuROM Release Control - Unknown executable {readPathName},{md5String},{entry.Size} - Please report to us on GitHub";
        }

        /// <summary>
        /// Helper method to check if a given PortableExecutable is a SecuROM PA module.
        /// </summary>
        private static string? CheckProductActivation(PortableExecutable exe)
        {
            string? name = exe.FileDescription;
            if (name.OptionalContains("SecuROM PA"))
                return $"SecuROM Product Activation v{exe.GetInternalVersion()}";

            name = exe.InternalName;

            // Checks if ProductName isn't drEAm to organize custom module checks at the end.
            if (name.OptionalEquals("paul.dll", StringComparison.OrdinalIgnoreCase) ^ exe.ProductName.OptionalEquals("drEAm"))
                return $"SecuROM Product Activation v{exe.GetInternalVersion()}";
            else if (name.OptionalEquals("paul_dll_activate_and_play.dll"))
                return $"SecuROM Product Activation v{exe.GetInternalVersion()}";
            else if (name.OptionalEquals("paul_dll_preview_and_review.dll"))
                return $"SecuROM Product Activation v{exe.GetInternalVersion()}";

            name = exe.OriginalFilename;
            if (name.OptionalEquals("paul_dll_activate_and_play.dll"))
                return $"SecuROM Product Activation v{exe.GetInternalVersion()}";

            name = exe.ProductName;
            if (name.OptionalContains("SecuROM Activate & Play"))
                return $"SecuROM Product Activation v{exe.GetInternalVersion()}";

            // Custom Module Checks

            if (exe.ProductName.OptionalEquals("drEAm"))
                return $"SecuROM Product Activation v{exe.GetInternalVersion()} - EA Game Authorization Management";

            // Fallback for PA if none of the above occur, in the case of companies that used their own modified PA
            // variants. PiD refers to this as "SecuROM Modified PA Module".
            // Found in Redump entries 111997 (paul.dll) and 56373+56374 (AurParticleSystem.dll). The developers of
            // both, Softstar and Aurogon respectively(?), seem to have some connection, and use similar-looking
            // modified PA. It probably has its own name like EA's GAM, but I don't currently know what that would be.
            // Regardless, even if these are given their own named variant later, this check should remain in order to
            // catch other modified PA variants (this would have also caught EA GAM, for example) and to match PiD's
            // detection abilities.

            name = exe.ExportNameTable?.Strings?[0];
            if (name.OptionalEquals("drm_pagui_doit"))
            {
                // Not all of them are guaranteed to have an internal version
                var version = exe.GetInternalVersion();
                if (string.IsNullOrEmpty(version))
                    return $"SecuROM Product Activation - Modified";

                return $"SecuROM Product Activation v{exe.GetInternalVersion()} - Modified";
            }

            return null;
        }
        
        private static string? WhiteLabelModuloHelper(string file, byte[]? fileContent, List<int> positions)
        {
            if (positions.Count == 0)
                return null;
    
            var offset = Math.Max(0, positions[0] - 32768); // arbitrary
            
            return GetModulo(fileContent, offset, file);
        }

        // TODO: at present, this will return executables that aren't PA-capable. I have to find a way to distinguish that.
        private static string? GetModulo(byte[]? sectionData, int offset, string file)
        {
            if (sectionData == null)
                return null; // TODO error reporting whatever 

            // This has only ever been observed on executables before the earliest version scanned (SecuROM 7.27) or on viruses.
            if (sectionData.Length - offset < 65536)
            {
                // TODO: probably needs to get removed since passing debug isn't possible, and this will trigger on pre-7.27 executables.
                Console.Error.WriteLine($"SecuROM section in {Path.GetFileName(file)} smaller than expected");
                return null;
            }
            
            var shorterSectionData = sectionData.ReadBytes(ref offset, 65536); //Arbitrary amount
            var readStrings = shorterSectionData.ReadStringsWithEncoding(charLimit: 29, Encoding.ASCII);
            var regex = new Regex("([a-f0-9]{29,30})$", RegexOptions.Compiled);
            foreach (var checkString in readStrings)
            { 
                var x = regex.Match(checkString);
                if (x.Success)
                {
                    if (x.Value != "1d47b0b0981cc4fc00a6eccc0244a3") // TODO: this might need to always be checked for validation
                    {
                        return x.Value;
                    }
                }
            }

            return null;
        }

        private static string CheckModulo(string moduloString, bool includeDebug)
        {
            var tempModuloString = moduloString;
            
            // Check if PA-capable executable is known via modulo
            var value = In80.TryGetValue(tempModuloString, out var gameName);
            if (value)
                return includeDebug ? $" - {gameName}" : "";
            
            // In case the first character was junk data that happened to be 0-9/a-f
            if (moduloString.Length == 30) 
            {
                tempModuloString = tempModuloString.Substring(1);
                value = In80.TryGetValue(tempModuloString, out gameName);
                if (value)
                    return includeDebug ? $" - {gameName}" : "";
            }
            
            value = NotIn80.TryGetValue(tempModuloString, out gameName);
            
            if (value)
                return includeDebug ? $" - {gameName}" : "";
                
            return $" - Unknown executable with modulo {moduloString} - Please report to us on GitHub!";
        }
        
        /// <summary>
        /// Matches modulo of PA-capable executables to known ones from 80_PA
        /// </summary>
        /// <remarks>Whenever 80_PA is imported, there are a few known mistakes that must be corrected
        /// Remove Google Chrome, it shouldn't be there and is most likely a reference to the author's other major project.
        /// "Nintendo Tiger Woods PGA Tour 08" should just be "Tiger Woods PGA Tour 08"
        /// "Final Fantasy VII Remake" should just be "Final Fantasy VII", although technically this must be confirmed.
        /// A few entries such as one of the GTA4 ones have too many leading zeroes.
        /// Some entries, most notably the Company of Heroes validators and Sam & Max (DVD), must be consolidated
        /// </remarks>
        /// When adding: convert all modulo to lowercase, this is how they're stored in the executable.
        // TODO: Verify no encoding issues
        private static readonly Dictionary<string, string> In80 = new()
        {
            {"a38dd5d1d6be7eed9b48eaaaaeeab", "Epic Mickey 2: The Power of Two"},
            {"02521fcb8cfa446e63788978050687b", "Grand Theft Auto IV"},
            {"002bf6b525ebefbdd4c25aeff4412a61", "Ys Seven"},
            {"162dcd779daafa567652c588a3f6eb", "Adam's Venture II: Solomon's Secret"},
            {"414d448850655e120dd9b5e3b8f49", "Battle: Los Angeles"},
            {"15f267eaea2b5814ca606b28b6b2bd", "Cargo! The Quest For Gravity"},
            {"2d9151eb1aca13488a247e0049e65", "Lego Star Wars III: The Clone Wars"},
            {"2cb4aedcc69b1cabb0e95e16feec09", "Men of War: Assault Squad"},
            {"650b577f238f00fac0765d146e05b", "Test Drive Unlimited 2"},
            {"67c28f29c39d09624be48c8e09eaeb", "Yars' Revenge"},
            {"4d0ec2fae65c604ece337f09174281", "Batman: Arkham City GOTY"},
            {"63f3e3e30aa861ce8167c73cb262bd", "Arcania: Gothic 4"},
            {"3b51d4bd3129c04287f1e61243f881", "Alone in the Dark: Near Death Investigation"},
            {"48b631fe128e46dde7df763830c675", "Blood Bowl (Legendary Edition)"},
            {"05447342fb5c8525d677e8ca63a747", "Dirt 3"},
            {"1b218375e5b39820d6424c7081be27", "Fable III"},
            {"938b0ca16b6052ad254a231c74f0c7", "Far Cry 2"},
            {"2bc7ed632a2a8124a87b8f9c878529", "Ghostbusters: The Video Game"},
            {"1cf9dff37f133d15d21cc4f5ade91f", "TRON: Evolution"},
            {"f516294e93fb13292d1fbac4100cd", "Medal of Honor 2010"},
            {"91d23a55e75c21c027416f13267a25", "Doctor Who: The Adventure Games"},
            {"273057dc91534b7552a3b9a1484b87", "Sir Pudding Wiggly"},
            {"756693090bfd7ff24c6d3fcb68898d", "Split Second: Velocity"},
            {"33ae73b7a6d321e18d9eec32746593", "BoneCraft: The Video Game"},
            {"7d5c89256f2cb21605c68082b9ec03", "BioShock 2"},
            {"1c7283bbd1982f282a7f01aa9c8105", "Final Fantasy VII"},
            {"221ca9bc36e3a796f44be26c99184b", "BioShock"},
            {"3b3af2483cc65c848855c85cf234e7", "The Travels of Marco Polo"},
            {"82fdeecc5df94feed32e6c8f2c23fd", "Ys Foliage Ocean in Celceta"},
            {"1ff41518621e80cb034bdf6dcb1cc1", "Grand Theft Auto IV - EFLC"},
            {"854dfe1017c1372529829e6f6eb35", "Bionic Commando"},
            {"96da099e9237d6ebcf187a16513d19", "ArmA 2: Operation Arrowhead"},
            {"6431f82291520429dd4fe812e9bc25", "Overlord II"},
            {"27476007dc0549d5b9c97a5ca595f1", "Sacred 2: Fallen Angel+Ice & Blood"}, // I&B uses DFA Unlock
            {"3a9988f47805aaa3e64002062e2667", "Batman: Arkham City"},
            {"b0a91039a54eb47ea42aef04fcc5bd", "Borderlands GOTY"},
            {"de182d578402cd973732ce26d27c1", "Dexter: The Game"},
            {"add5baf89353707b0c80d078d0c789", "Spore+(GFW)"}, // error?
            {"6c3d97adef0eae6fbbb32484d2603", "Mass Effect"},
            {"ab3b9890860692232c0142c3858963", "Command & Conquer: Red Alert 3"},
            {"1252b3ff5c1a2c55baafc3524e18fb", "Need for Speed: Undercover"},
            {"75b5f978e7baa0131175b842a05f1", "Batman: Arkham Asylum GOTY"},
            {"6983ff0412fc4d5ab1d8dea9134483", "BoneTown"},
            {"a49bc17bbdc11e4ed58bca6262125", "J.U.L.I.A."},
            {"95487472555a212cd1d8bcd8c00377", "TRON: Evolution (Russian)"},
            {"224949c82f0fb49b5ba4061fc0cdc3", "Burnout Paradise: The Ultimate Box"},
            {"3509804f6337a566d145d9dac8ecf5", "Mercenaries 2: World in Flames"},
            {"73ff4d6a6d114d9de94316ce24a95f", "Mirror’s Edge"},
            {"c880b457b93120f7fc2ddf12aa2b9", "The Godfather II"},
            {"1af9354a73ef892fdc84807ba1472f", "Manhunt 2"},
            {"39d5e694ecba73d18e03d4a63a9fd5", "FUEL"},
            {"1a456cbdaeb0b67e95fe67e5ee5cad", "cdBook (Latin)"},
            {"12208ddd625441678adfc9a32782cb", "cdBook (Greek)"},
            {"21211df4f979daed156b062e915ef9", "Nancy Drew: The Silent Spy"},
            {"34d507b82fda088190936453fc7bb3", "Tale of Wuxia: Prequel"},
            {"e7332b2bc930e858d3af4fd4af1a7", "Air Raid: This Is Not a Drill!"},
            {"3e474411224172dc627a4b044698d7", "Panzer Killer!"},
            {"10b4ab259f805b7a92724bec55377f", "Red Shark"},
            {"1467e8202b4d6bcaec825b595ff581", "The Dark Eye: Chains of Satinav"},
            {"7ef0105e18e4ae331f31bf7a6d43af", "Dead Space"},
            {"459fc44c2edaeea9e8f5060075a09b", "Operation Flashpoint: Red River"},
            {"10ccb32ec03c15cb5b78e391b007cd", "Lego Pirates of the Caribbean: The Video Game"},
            {"6fe5e87bce4cbef422f771d3172ee5", "Wolfenstein (2009)"},
            {"143aa12ffe3d249fc9429cb6e28cb5", "Brave: The Video Game"},
            {"77179e4410e58a0eb634e14043ad51", "NBA 2K14"},
            {"b1876f2b3f18bf18f9cdea2119693", "Pro Evolution Soccer 2014"},
            {"a1477c02dca5251815bbb5aa3df6f9", "Pro Evolution Soccer 2013"},
            {"1081d8b881c3ce565df4c26c967fdb", "Command & Conquer 3: Tiberium Wars"},
            {"1cad0c0ec120fbcfbe3d8e21a2f85f", "Command & Conquer 3: Kane's Wrath"},
            {"5707f2b42739843c12eab0bb1a5931", "Need for Speed: ProStreet"},
            {"5985a629de4180f6a7dd2cb355e013", "The Sims 3"},
            {"1003e12c0ebb666975041481bbd485", "DENUVO Insider"},
            {"e69fb98089918a7543e15ed250d987", "DENUVO Introduction"},
            {"47663ec5e972d151996bc6dca1b833", "Bone: Out from Boneville"},
            {"157dbc6cc9bb855a74bf71e56ee46d", "Sam & Max|Sea.1/Ep.1-6 (DVD)"},
            {"7e3b846410f0c06a0b5635b66c20a3", "Sam & Max|Sea.2/Ep.1: Ice Station Santa"},
            {"7ea4bb3c7d28b3ae0a6c59f7eb1d23", "Sam & Max|Sea.2/Ep.2: Moai Better Blues"},
            {"7e966fd36094598e1f182a9789085d", "Sam & Max|Sea.2/Ep.3: Night of the Raving Dead"},
            {"7e77df607e00632e736fff8e1aa847", "Sam & Max|Sea.2/Ep.4: Chariots of the Dogs"},
            {"7ec3c9d324923f09eee03a7d943f0f", "Sam & Max|Sea.2/Ep.5: What's New, Beelzebub?"},
            {"38eb8aadd1593152ca74038054156f", "Tales of Monkey Island: The Trial and Execution of Guybrush Threepwood"},
            {"38c03cc656eaaf0672e874a52b5e69", "Tales of Monkey Island: Launch of the Screaming Narwhal"},
            {"6d7e29bd130ac5bdec79eea0e3dc5", "Puzzle Agent: The Mystery of Scoggins"},
            {"38f05ae3ca5b2ed5c9b47fb164ce7d", "Tales of Monkey Island: The Siege of Spinner Cay"},
            {"17a36834ea59597923112b6eaebadf", "S.T.A.L.K.E.R.: Shadow of Chernobyl"},
            {"80834326d3d2cb02a19f6a55b167ab", "Sam & Max|Sea.1/Ep.3: The Mole, The Mob, and the Meatball"},
            {"806ee5b9e6827c9122a804db173967", "Sam & Max|Sea.1/Ep.5: Reality 2.0"},
            {"80492e2befc853e8099641e7128d09", "Sam & Max|Sea.1/Ep.6: Bright Side of the Moon"},
            {"6a4c20c008ab0b63f87786120ab975", "Sam & Max|Sea.3/Ep.1: The Penal Zone"},
            {"6a704013c7fc0946ca084cc244757b", "Sam & Max|Sea.3/Ep.4: Beyond the Alley of the Dolls"},
            {"470d3a0734c24ba697821783f55507", "Bone: The Great Cow Race"},
            {"38b0681abefb69d781bfe02dff9a49", "Tales of Monkey Island: Lair of the Leviathan"},
            {"e16318b1af374aafdf7080f147c9df", "Strong Bad's Cool Game|Episode 5: 8-Bit Is Enough"},
            {"2a74d920dcbc68a8977b0ce53958c9", "Strong Bad's Cool Game|Episode 3: Baddest of the Bands"},
            {"e1333616a46462c79851875f2a5d5d", "Strong Bad's Cool Game|Episode 4: Dangeresque 3"},
            {"e14b756caafc379026c74085c2c93d", "Strong Bad's Cool Game|Episode 1: Homestar Ruiner"},
            {"e100b960e1731e289dc83ad2aae287", "Strong Bad's Cool Game|Episode 2: Strong Badia the Free"},
            {"4beebaf49605880691d5f4e06ca6f9", "Telltale Texas Hold'em"},
            {"f51086ce95b63117249208a844225", "Dark Messiah of Might and Magic"},
            {"1bece4c435474dc44716f312ad5ab5", "Divinity II: Flames of Vengeance"},
            {"29549764f2dd04a7ddfe6557919277", "Divinity II: The Dragon Knight Saga"},
            {"b63cb41edd4ad08c24cdb052cb3b05", "Cities XL 2011"},
            {"c4cc06c6c9a10a31d95cb56edbfc75", "Tomb Raider: Underworld"},
            {"3248d59cdf5afe00ac4cd47b8b7159", "Race Driver: GRID"},
            {"2411b35d13ff8997ff37552cdb948d", "FIFA Manager 09"},
            {"b296f8cf2a16580dd14937c321bdf", "Hotel Giant 2"},
            {"20bf1e8f3b20f4d2385d0208cd6845", "Puzzle Quest: Galactrix"},
            {"cbaf8578701ae84bdd5ac862ca38f", "NBA 2K10"},
            {"20772a13a15d12a4a2843bc2e18d5d", "Drakensang: The Dark Eye (German)"},
            {"9252e736393c9798a0eb03abf2276d", "Neverwinter Nights 2 (Gold)"},
            {"37eb12599558d1afb4824203050b19", "Star Wars: The Force Unleashed II"},
            {"3a4eedf4307e297c32a113101589bd", "A Farewell To Dragons (preview)"},
            {"2d4088a5e18e7b2ea4dcdce75a1d13", "King's Bounty: Armored Princess (preview)"},
            {"3450689dcffbfa2503c0410cb4916f", "Men of War: Red Tide (preview)"},
            {"326bcc0a16832ba8bc5d4f9f7f21c7", "NecroVisioN: Lost Company (preview)"},
            {"395ddf81759754cf94ffd87730ee1f", "Real Warfare: 1242 (preview)"},
            {"547d405f97884dc442a231b0beb13f", "Reign: Conflict of Nations (preview)"},
            {"25d7f1b66a43287e9aabd173f03985", "Stealth Force 2 - PC"},
            {"2b4acdb812f044cb39811ad50bbbb3", "Where's Waldo"},
            {"2f36a4bb67ba65dd5b4451d67ce5f9", "Mahjong Wisdom"},
            {"7a1d10bb8cf536b0cadec7f1bcd6a7", "Dark Void"},
            {"930564a49111cbc33dacd3beb681f1", "High School Dreams"},
            {"7a9f12b3ebd68366109249baa38287", "Crysis"},
            {"c7c259ef9480cd854d4b533b4001b1", "Crysis Warhead"},
            {"37af9c807be3d127ac664ad730c7bf", "Age of Booty"},
            {"d533856c05a1f99a9e6707e30341f", "Flock!"},
            {"a4703f1acf2a81a3ce3e644011383", "Dark Void Zero"},
            {"1fd4c0870c6a9e56e4c6e5aa99edab", "Daisenryaku II: Campaign Version (China)"},
            {"de7be358590b9909e38acfafe239f", "phase-6"},
            {"45a5e249fcf4f35a8202c8517b833", "18 Wheels of Steel: Across America (2003)"},
            {"b86158547d628b6d724d6fb8c6f53", "Toy Defense 2"},
            {"a0c45f715a49e3e570bf92df2980b3", "Empire Earth II: The Art of Supremacy"},
            {"10b63f8a64fcd759f2465a2255bb3f", "Blur"},
            {"3b316b6b97fec79a904a73b1c2fe2d", "Mount & Blade: Warband"},
            {"6a35a8fdf186dcf034cce780b7da87", "Cars Toon: Mater's Tall Tales"},
            {"16465f4a3b26361b546a154cc6edad", "Conflict: Denied Ops"},
            {"5b5fd729ff4a4f5ef550f982e978d", "The Sims 2 Shopping Edition"},
            {"aa3d982b9a56ea5dcce502878ba957", "Stronghold Crusader"},
            {"ce1e78bacb0cb53e2870a72e23f1d", "My Golf Game VTree"},
            {"2c75389b4ecfa657d7e36335ef46b7", "FIFA 11"},
            {"284868f013e051ea708fa2998efa47", "International Basketball Manager Season 2010-2011"},
            {"a8c173a689e58b710b38821f6449c3", "2K Sports Major League Baseball 2K12"},
            {"12f24802e14ec49c1f1c7eeb7ca603", "Adobe Director 11.5 (A0102084926-0101)"},
            {"7ffc55fe8d49c40170ac36f2f70673", "Basisinformationen Uber Wertpapieren und weitere Kapitalanlagen"},
            {"6f3957ea8bdf207e37b15f26781319", "Adobe Flash Player 10.0 (A010164838-A511)"},
            {"d86a58a50c4139108c44ad3a734f9", "More! 4 CD-ROM"},
            {"5df8e7684e106b3e1028fd94cafb31", "Vedere la tecnologia"},
            {"b969572dad7ac5d9ed2d3e529efed", "Interaktive Sprachreise: Sprachkurs 1 English"},
            {"67f1857c70d76aef3accf47b0694d3", "ShowMe AAC 2.0"},
            {"1e4d724af6ab73593497ef4725101d", "English goes live COMPACT – ACTIVEbook"},
            {"17d49c36b8fcb7ad5f69865d0908c1", "Tecno Cloud ActiveBook"},
            {"20e9400120309cfa5d821f094796f9", "Pearson Longman"},
            {"6263ad2d89530086b3d2baab89bcd5", "Priberam Dictionary of the Portuguese Language"},
            {"1b684ccba5cfaf0d24da758b3d43a1", "Cradle of Persia"},
            {"ab3946fc2b6d4fdf1cab2a983fd3d7", "The Secret of Monkey Island: Special Edition"},
            {"1d2652f57bde52856a7fdd71d85f7d", "Feeding Frenzy 2"},
            {"2484f8e7f221d9c3b0165e55892723", "eText (A0102384122-MTVR-NO)"},
            {"5d7527ddf6d3c27fced1f6f89f0407", "TRON: Evolution (Polish / Czech)"},
            {"2204af33cc14826bebd43e3851cad5", "cdBook (English)"},
            {"22dd42fc93e53c8975b0b0a8c98ccb", "Test Drive Unlimited 2 (DEMO)"},
            {"ba3ed17f113d92d124709d820179f", "Legends of Atlantis: Exodus"},
            {"4096352a23661eb4369cd2a17d763", "Cody Pops the Case"},
            {"97dc8a817f2404eb301b6709b56fd5", "Cradle of Egypt+Fairies and Pharaohs Bundle"}, // error?
            {"b343513174fbcd313854a15c41385", "Living Legends: Bound by Wishes"},
            {"3081c3f2ebc327061727d867e04dd", "WindFantasy XX"},
            {"a3ab1238a9255a6705d63005c51fc5", "Macromedia Projector (VFR02_01)"},
            {"4e6ad2e45c6fef9c178496c4c39eeb", "EXE Player for SWF"},
            {"6e213687795abfb2f582d242447be9", "Aztec Tribe"},
            {"8ad81a22b66d32cdd68ad6d968eb79", "Hotel Dash 2: Lost Luxuries"},
            {"a869e8e84c8957d3fdbb731a8245f1", "Take Away Food Safety Game"},
            {"110ded1e6fdb2216b6d2cb52d3cd07", "Burger Shop 2"},
            {"12cd4a31f9cb6137f2fa702aac9fd9", "GCSE: Essential Maths"},
            {"1863a37b611ea3f67b19dabe18032b", "Pearson Longman (A0101624388-0101)"},
            {"adc2a6beae21c0ae8f960f75ca3253", "Mushroom Age"},
            {"9f15b8503bfdd74180c49d2b1dbb5", "JAA ATPL Exam Preparation"},
            {"82ad10cc847445411f7d1ad5497a49", "The Sims 3: Pets"},
            {"3ae54b7f66fb0206c448ee6b087579", "CellFactor: Psychokinetic Wars"},
            {"5d2628cf00c70140f74e98fd6592a7", "Nightshade"},
            {"1c2b11c28530cb72638f4be488b06f", "The Legend of Heroes: Trails to Azure"},
            {"11c11ea9352faab6384921800ee1f1", "The Legend of Heroes: Trails from Zero"},
            {"114a54bace5df661285277a640c3b1", "Empire of Angels IV"},
            {"9245eabed70772c21cf50701b12b4d", "Vantage Master (China)"},
            {"2bdbf90413163f9ae17b2ed0e473a1", "Ys Seven (China)"},
            {"8282040a04a666e0011987532a3419", "Ys Foliage Ocean in Celceta (China)"},
            {"df5aa5bfda10f86c8ed0dc3cc7c31", "Norn9"},
            {"c1eb9503d70b5a48290572728f9b3", "Batman: Arkham Asylum  (GFW)"},
            {"1d24ef9f1b01079c64f48add75e0ef", "Bejeweled 2 Deluxe (China)"},
            {"49007aa07708e4f2b8cd2c5406062f", "Blood Bowl"},
            {"1d1b57c0a3ba0de2253da160046dcb", "Chuzzle Deluxe (China)"},
            {"19a57883efafbbc2a6745711ba605f", "Command & Conquer: Red Alert 3 — Uprising"},
            {"8de4c2d8fd192781fa83ca661bf88b", "Dark Void (American)"},
            {"966453603c8b01ad462383e486b6f9", "FIFA 09"},
            {"2366daf9c3a83d6a7cc832885ab321", "Legendary (Europe)"},
            {"d1466b26ddb8a719a1dea890b5b295", "Littlest Pet Shop"},
            {"9e764153b0543fd27bbc733bed261", "Max Payne"},
            {"1b07b7fea488a489d77f9bcb2be24b", "MotoGP 08"},
            {"68afe0d5fd9e67889bc8e85d092c35", "NHL 09"},
            {"1d43cb209aaa22588a870af318f5ef", "Peggle Deluxe (China)"},
            {"783e3b1456ccdb55594334e1e4a7a9", "Split Second: Velocity (Russian)"},
            {"87db7a24a031be52442e7030802ab", "Spore Creature Creator"},
            {"e1f13cb8e680c4edfb96bb2aed0229", "The Lord of the Rings: Conquest"},
            {"426e214df03e965f8a63e8847a43ef", "The Next BIG Thing"},
            {"1d3853a1ac764021fbca610b7b3657", "Zuma Deluxe (China)"},
            {"44c0be6489406e5e6553970cc1f4e3", "IGT Slots Paradise Garden"},
            {"e672f2bc3adf5f49e4c4ddeb3f2c9", "Major League Baseball 2K10"},
            {"20fe46889c247b6c778850c74c64e7", "Nancy Drew: Alibi in Ashes"},
            {"4f9afeca999f4b69349faf19bddf59", "Rugby 08"},
            {"f481b9a6497dfcb093553a8da62cb", "Besposhadnyi patrol"},
            {"1d461d548dff2c202325c6c5e781bf", "Insaniquarium Deluxe (China)"},
            {"ab88bd0190437dd4931a545e870ab7", "Max Payne 2: The Fall of Max Payne"},
            {"1d2b54eee605275c751498970006f1", "AstroPop Deluxe (China)"},
            {"1d1b0fc8533e3a26cd60ec889a3207", "Big Money! Deluxe (China)"},
            {"b08a121b28f2925685cff57a748fa3", "Death Road"},
            {"1d335f4c6009e6be93f01e7eb5cd3d", "Dynomite Deluxe (China)"},
            {"4c3b270042332deefa14ea6d96c00f", "F1 2011"},
            {"7053dd109968d89b7048096d7f805b", "Guardians of Graxia"},
            {"5e3c71cefeb89d6c2761116d12bd4f", "MUD - FIM Motocross World Championship"},
            {"7cad9b7a2c1b46c5dc3a1962ab4d99", "SBK Generations"},
            {"50f45aa94579d635bd3ed693ddd32d", "Shattered Origins: Guardians of Unity"},
            {"35fc6144195eb993246e060a60f10d", "The Sims 3: World Adventures"},
            {"4803c8827c39d1641c8b1bad319e41", "The Sims 3: Ambitions"},
            {"60bfce5f67546fce58f1205ba7ff55", "The Sims 3: Late Night"},
            {"4c2a26d82840ddda55cec4f180339", "The Sims 3: Generations"},
            {"7dafb5eba60b3cfe7a2d012d4a1477", "The Sims 3: Showtime"},
            {"97364d49a88166fe7d9cee5e5b29f", "The Sims 3: Supernatural"},
            {"bff55f65173b8a34cf1c1610a4b23", "The Sims 3: Seasons"},
            {"19bf7e3eb4a2f990b97af0d009b3a7", "The Sims 3: High-End Loft Stuff"},
            {"15c7b95be02f72a0a3462a45219953", "The Sims 3: Fast Lane Stuff"},
            {"5fc80a2883ef36303b5a15ab397e6b", "The Sims 3: Outdoor Living Stuff"},
            {"7f97550cec1d26cda0e84566fd6463", "The Sims 3: Town Life Stuff"},
            {"125eb71b0299894bfc9734b92cc2b1", "The Sims 3: Master Suite Stuff"},
            {"3f15a1657a924a116fa1d4eeaa56b3", "The Sims 3: Katy Perry's Sweet Treats"},
            {"104cdf29947105806e317edd160305", "The Sims 3: Diesel Stuff"},
            {"a9fbf14250e9312dfcac4510be77bf", "Ankh 2: Heart of Osiris"},
            {"19fa5cbdb77b70018edc1e48be987d", "Ankh 3: Battle of the Gods"},
            {"23a1ed3ac01004f0863031bbb0440d", "Around the World in 80 Days"},
            {"af4e8ea7860b7a7a8f11d3499f901", "Bookworm Deluxe"},
            {"f951b232e8b1240c4fda1f3a17995", "Borderlands"},
            {"3706e121c61e423a3cf942dec172fb", "Bubble Town"},
            {"152290bf6cf6e2ec858f459079043", "Call of Atlantis"},
            {"6bee78261d90e5763f2c26a199a65d", "Chainz 2: Relinked"},
            {"6e7506ce96aa4c923d77f42da95cd", "Cubis Gold"},
            {"14e66cba0ef2eff1ebaca9dc9b6311", "Cubis Gold 2"},
            {"79ce942f54cb81d82843b1fad9e167", "Disney Fairies: Tinker Bell's Adventure"},
            {"85edef527071bdc0aac6c1f1b178b", "Family Feud 3: Dream Home"},
            {"3cd22a3854ff72d6499f444a814923", "Fishdom: Spooky Splash"},
            {"1b552c9569cac41de720b48ac70cc1", "Hitman 2: Silent Assassin"},
            {"70db336bd9c87618c8e8f314e86ae3", "Jewel Quest 5: The Sleepless Star"},
            {"3371055499066ea44c7c94fd69770f", "Poker Superstars III: Gold Chip Challenge"},
            {"af919d0be7b9327a6ab92cb590b48f", "Ranch Rush 2"},
            {"3a5a90e838f9c6a0ced5f2ea4953b9", "Resident Evil 5"},
            {"78c900096a870dce4f9b493049a135", "Runaway: A Twist of Fate"},
            {"a0ff1ad44e716da9ba200cc9e84309", "Slingo Deluxe"},
            {"254995514a963089a6c397fb6191cb", "Starpoint Gemini"},
            {"261a6c003555ec20551429b318a3ab", "Super Text Twist"},
            {"6ddcfddd92b013b7aca6ffd692d4f9", "Text Twist 2"},
            {"2ab11a8cde90a4ff03df63486e37d3", "The UnderGarden"},
            {"bb245df3ae03d5efd33f99c3607d9d", "Ancients of Ooga"},
            {"56a12178eca11b052fbf4e5c9a7289", "Anomaly: Warzone Earth"},
            {"148532a316854bfecac3ec8881fbf3", "Backyard Sports: Sandlot Sluggers"},
            {"d93f1f7956e4e1f6df3a60d7a99b55", "Blue Toad Murder Files: The Mysteries of Little Riddle"},
            {"28af17bd0b6e2300f72f8567a88567", "Chernobyl: Terrorist Attack"},
            {"6075b17be895c9cfa4271ced75e87", "Cities XL 2012"},
            {"8c969187c13a8d6c59b39d487f302d", "Combat Mission: Afghanistan"},
            {"fb9246c077a8e53d321d329badfab", "Dead Mountaineer's Hotel"},
            {"add23cdacd7c7ac853336b7e090473", "Drains"},
            {"a38625e789da0698181fcbe92e4a0d", "Haunted House"},
            {"12d607bb0099046b8ad98f2bb5ca13", "I'm Not Alone"},
            {"143dfe92fdfe9764c63d2702bcffbd", "iRoll"},
            {"55dccce7aede815538a1963e415823", "Konung III: Ties of the Dynasty"},
            {"36a264fbe9b7d91d3e31116ea54d3", "M.I.A.: Mission in Asia"},
            {"5b85e6415931ab57ea437e313bc97b", "Puzzle Chronicles"},
            {"4d8499d2ea4e421b45b4af0cece09", "Shira Oka: Second Chances"},
            {"29f5846a1357ab361017523a011799", "Star Sentinel Tactics"},
            {"58ec9553a6467f556cd51cd9b11b2b", "Tanita: Plasticine Dream"},
            {"31380884e3bfe18dffe18632b80f45", "The Way of Cossack"},
            {"3f58cc7e04663be9ac95b461596b47", "The Whispered World"},
            {"3f51fb8cb7e95218fad8429424b6ef", "World Gone Sour"},
            {"2a736644e38ae956c4dcf3eaeef2a5", "Deepica"},
            {"a0ea5fc7046a8845b0a59ba52fda49", "Dracula Series: Part 1 The Strange Case of Martha"},
            {"140b105118814afefef7c4267bbd6b", "Dracula Series: Part 2 The Myth of the Vampire"},
            {"4d6d944d3d2001da0beb0bea649e57", "Dracula Series: Part 3 The Destruction of the Evil"},
            {"97378f7a160a49cf25f31d2a04e2d7", "JASF: Jane's Advanced Strike Fighters"},
            {"ab791f704680f08f007dfef8987497", "Kaptain Brawe: A Brawe New World"},
            {"1ef98f370edfef74be9f9547d97b8b", "Murfy Maths"},
            {"c532d48250b95a3866844d910f9967", "Pro Evolution Soccer 2011"},
            {"401ccbebf310279d982e872e7afd9b", "Steel Storm: Burning Retribution"},
            {"4e6e7a0018149a53d9a8543e272645", "Take On Helicopters"},
            {"96c0fd63294437992b36a192bc9fdb", "Warfare Reloaded"},
            {"10e11be542b3024a3234aeb9b5b9b5", "Caesar IV"},
            {"14b6de19d0d3140b4ffa08b5da20e7", "Dungeons & Dragons: Daggerdale"},
            {"109f38a47951f1e304b54b7273d8bf", "The Settlers II: 10th Anniversary"},
            {"18fc730422c5854b964a49a35af649", "Sniper: Ghost Warrior"},
            {"f8cde0c746e91bbe918eb2c465579", "Venetica"},
            {"2e89b0fe65cc04f41e808fea2858ff", "Wallace & Gromit's Grand Adventures, Episode 1: Fright of the Bumblebees"},
            {"2eb3bb2a990a7f1f6f70b09072e6a7", "Wallace & Gromit's Grand Adventures, Episode 2: The Last Resort"},
            {"2ea0dd388e0b39fe3bb990b59bca3d", "Wallace & Gromit's Grand Adventures, Episode 3: Muzzled!"},
            {"2e8b10e4e668b0284e3f1c631ecd73", "Wallace & Gromit's Grand Adventures, Episode 4: The Bogey Man"},
            {"8065c1c23c869b70345d4c0d5c9669", "Sam & Max|Sea.1/Ep.2: Situation Comedy"},
            {"6a3d675d2df49c8478552ebd1942e1", "Sam & Max|Sea.3/Ep.3: They Stole Max's Brain!"},
            {"6a1ebc441dbb8e0d135bc8d1b2dc4f", "Sam & Max|Sea.3/Ep.5: The City That Dares Not Sleep"},
            {"38ba41b2744859ca6ce032a1dab981", "Tales of Monkey Island: Rise of the Pirate God (Digital)"},
            {"a2962b154fda1085a64b7dcdbc1dcb", "Hunted: The Demon's Forge"},
            {"239cabb96b08d038fb04cd8a09d093", "Tale of Fallen Dragons (China)"},
            {"bc0e71b095b025aaeae63816d9f7a5", "WILL: A Wonderful World (China)"},
            {"1cb766af94a877ebda1bda46acf3d", "Achtung Panzer: Operation Star"},
            {"f57b1d0620d3bff3685add472b12e7", "Men of War: Condemned Heroes"},
            {"2384d1d6c4707abb01ab9e40f023f7", "Men of War: Vietnam"},
            {"27d1515e143fcf762dae82b45c6097", "Sam & Max|Sea.2/Ep.1-5 (DVD)"},
            {"8a59e5f3b4815d17d55a194f082d5f", "Strong Bad's Cool Game|Episode 1-5: Homestar Ruiner (DVD)"},
            {"8021fc50df50ec468af9ea7b03e6fd", "Sam & Max|Sea.1/Ep.1: Culture Shock"},
            {"4dd4e86879325d7c8790643f1293bb", "Remember 11: The Age of Infinity (China)"},
            {"50774ff475a309c579445eca3045ef", "Pixeline: Jungleskatten (Danish)"},
            {"86c3ac44c4b2dffb8ab1d45ba0d733", "Disney's Chicken Little: Ace in Action"},
            {"8a9043e149d4ab28a0aec9466d1be7", "Diner Dash 5: Boom!"},
            {"6f57685c1523c815542558a0cb4347", "WALL-E"},
            {"1e9759cd2d57fa3f8dc4bd55195f1b", "Divinity II: Ego Draconis +  _ (German)"},
            {"f4b072931ebe648610665f9624b79", "Donkey Xote"},
            {"3d55425a6d6b0ddca87efa5db7ada3", "Drakensang: The Dark Eye"},
            {"465078dc1f46288bd1d1d470495a0d", "Drakensang: The River of Time"},
            {"30b3d17ea34b717f09f0cfe4762a13", "Driver: Parallel Lines"},
            {"357167793a6c9a5bfc1be4de3eaacf", "Dynasty Warriors 4: Hyper (China)"},
            {"c0a56acc58c1fa3db0d285adb010b5", "Dimension M: Evolver"},
            {"66a13e7423398cb2813d11a1db52b", "G-Force (Europe)"},
            {"385b3b205f2546d4f4d9928be6135f", "G-Force (American)"},
            {"86efff1274b2aeeba5146e8cf5c8eb", "Kung Fu Panda"},
            {"1d6460807aa77b92048af128cbc541", "Legend of a Rabbit"},
            {"b623bc62beb8b6b792faa8a812038b", "Lemure"},
            {"2c9cec3dc202960e1721c16757438d", "Lottso! Deluxe"},
            {"122a7b6aa66bc2843a96687917f1ab", "Medieval II: Total War"},
            {"ee48ccfef9c1c1b968fbb632aebbf", "Monsters vs. Aliens"},
            {"6e534034cb6565c1ac2bce74377ed1", "Slingshot Puzzle"},
            {"1db89b6bb78c3ea8a1ce354e149d9f", "Soldier Vs Aliens"},
            {"1797a907f84b020295269177bf658d", "Disney Winnie the Pooh"},
            {"2ad1323f57d02990685d02c8039a89", "1half Ritter – Auf der Suche nach der hinreissenden Herzelinde"},
            {"4429d44e902a2e331f556d3f3e1ab", "ArmA 2"},
            {"346e5b67ba4acfd18e37c6e71a122d", "Damnation"},
            {"a88dd8f75d8bab6327743cec38e03f", "Deer Hunter Tournament"},
            {"3dfe5e1c0f230e640650eb9ce9057d", "Devil May Cry 3: Dante’s Awakening"},
            {"c75cc264c43192816e2fa57c2200df", "Devil May Cry 4 (Europe, USA)"},
            {"b6736d0e535d74a12fc4eee1f5129d", "Devil May Cry 4 (Russian)"},
            {"428428d50d49e6f54088d284a2436d", "Dirty Dancing: The Videogame"},
            {"21d0416981c4b41cd9a12219add0b5", "Disney Bolt"},
            {"1e11d3281e6588a730a22a02ca5ab3", "Disney Planes"},
            {"652fbf0f9c34eb81d2dbafeb371cd", "Disney Princess: My Fairytale Adventure"},
            {"651a9a5b1c68f51523b4c3d6d89203", "Disney Universe"},
            {"712df50d891968b547d57987863715", "Disney Cars 2: The Video Game (Russian)"},
            {"1fd7a05cb0efce556dfd7e9057b81b", "Disney Cars 2: The Video Game (American)"},
            {"17c5d7c4db51a2d9cad2450ea8623f", "Disney/Pixar Toy Story 3 (Europe)"},
            {"50a2267b0449d9542012f4f7104e7d", "Disney/Pixar Toy Story 3 (American)"},
            {"6ede4f799b9b642630e5e3fafd2863", "Disney Up"},
            {"331b14772ab9b4c277a001a603ca5", "Fallout 3"},
            {"2f77dedfbefaa3df57a7f7f6ede551", "Hellgate: London"},
            {"7c4c86440d3a9b30823e6949e52177", "Medal of Honor: Airborne"},
            {"2cf4aea0f5adbadd184b43871f4bf5", "Pirates of the Caribbean: At World's End (Europe)"},
            {"343f545e7c17d5fc96c5c11bfce27", "Pirates of the Caribbean: At World's End (American)"},
            {"27038abddafe306ed456dcebf1f8c1", "Spider-Man: Shattered Dimensions"},
            {"127bb93c75bd8f30e827a485579b85", "Tangled: The Video Game"},
            {"20dff8074b2fc8fb517aa6e5a90aef", "A Vampire Romance: Paris Stories"},
            {"cd1eebfbc083176c1bd21b7e2642d", "Adelantado Trilogy. Book One"},
            {"21154f3a1ed59fa7818bf3dc0d195f", "Alice - Behind the Mirror"},
            {"2053d9228c8daf1e8c6cf32c94081", "Ancient Adventures Double Pack"},
            {"1181e548a9e18a2de39bc572e1c135", "Artifacts of Eternity"},
            {"2b324d90f1f0adec029a8b79b5a4ef", "Atlantic Quest: Solitaire"},
            {"8a65b7e74338508e6c811984c7dddd", "Avenue Flo"},
            {"8acebd0feabe0517cb42406990f97", "Big City Adventure: San Francisco"},
            {"1537447c7f3773e23460bbe5dc7ab9", "Bistro Boulevard"},
            {"b396111cd6c25d7baa6481c79b17f", "Botanica: Into the Unknown"},
            {"2a49a91e9db36f2d4e6f1146f46061", "Building the Great Wall of China"},
            {"19fec2d2a75d3d0017e7b23d79ef83", "Cake Mania: Lights, Camera, Action!"},
            {"20a500e758a87e52940f6e1856d97", "Call of the Ages"},
            {"de0f41c4dc8d78986238af0b35ef9", "Chronicles Of Albian 2: The Wizbury School Of Magic"},
            {"6e163a943d3d896f1673bcb334db9f", "Claws & Feathers"},
            {"8a4d397e384a320bb7d72085f988f1", "Cooking Dash"},
            {"8a9b59af7c5a0b9b7cb21430bc91a7", "Cooking Dash 2: DinerTown Studios"},
            {"fbaf557f2e5008504e13d58d91a9b", "Jewel Master: Cradle of Egypt"},
            {"7f55101cacd751a909c50a2df7353", "Jessica's Cupcake Cafe"},
            {"b31c48549d6cef6d1e4d3be1d9b11", "Deal or No Deal"},
            {"8abc69a561f55f236f2c9f1a309115", "Diner Dash: Seasonal Snack Pack"},
            {"dc9a32d45175bc03a69b419f9d176f", "House M.D."},
            {"20a3624b93c581e1e7e56f7e5334f", "Dragon Keeper Double Pack"},
            {"6e4bf69eb8a964f5f81378d5bc4ac3", "Fairy Nook"},
            {"6e7c35ab93d7c93f0667c50467374b", "Farm Frenzy: Viking Heroes"},
            {"6e7d6e2180f9663a92f29f1795545f", "Farm Frenzy 4"},
            {"19673129202c974ae9941438f855cf", "Farmington Tales"},
            {"b31999e918749f9fde3583250e6bf", "Fierce Tales: The Dog's Heart Collector's Edition"},
            {"200926b06ac75851d667d01f88a61", "Fishdom: Depths of Time"},
            {"20d4de95aaca1beec1adab3e5af07", "Fishdom: Under the Sea"},
            {"1962a69fce03e8bb33920c2c6aa77d", "Gardens Inc. – From Rakes to Riches"},
            {"20e4767bf3a207640e70713fda09b", "Gardenscapes: Mansion Makeover"},
            {"20a9b08aa68caed7fae92769974c5", "Gardenscapes 2"},
            {"201930cd42159bb97e1de7a01684b", "Gardenscapes Double Pack"},
            {"2114d03b70788503cedfa535db0f13", "Garfield's Wild Ride"},
            {"8a7a874f0408e1d5713574ee3a3345", "Gemini Lost"},
            {"6e3966fe22c41d9b63a20354437c91", "Gourmania 3: Zoo Zoom"},
            {"b3851f66ef9f96eba94ddb0d17427", "Grim Tales: The Wishes"},
            {"b491b24dc0339ecb8e82ebad9c55b", "Hallowed Legends: Templar"},
            {"b3faace05b9086c59e1d6a4e8acc3", "Haunted Train 2: Frozen in Time"},
            {"210189d0cc5bb08d0bed749a54ed77", "Hidden Files: Echoes of JFK"},
            {"21005729935450fa1040584e701aff", "Home Design 3D: My Dream Home"},
            {"8a8f3500b338d95a68e1103c9c2b61", "Hotel Dash: Suite Success"},
            {"ae73f6a22802676636b08fed27e555", "Iron Heart: Steam Tower"},
            {"000c998a0f5e660e9e5642a6eb626965", "Island Tribe"},
            {"ce1e1dae4919d6de0a0aeaf7b20e1", "Island Tribe 2"},
            {"ccc6243f90d6de316a30989728a6b", "Island Tribe 3"},
            {"c96c839294ec7477897066c65a90f", "Island Tribe 4"},
            {"6c0448871e0e7f99c55e3f6b625c37", "Jewel Match Twilight"},
            {"1118ddc804fe81a709a64155eb0589", "Jewel Quest Solitaire"},
            {"599688c13f99f4ca5bfaaf86db6b1", "Jewel Tree"},
            {"474f1e554907d90ae4dabc6971a9b5", "Knight Solitaire"},
            {"b32596035f522a3b0b4c0c5264b13", "Legends of Solitaire: The Lost Cards"},
            {"19b7f5242e4c54b33fbb59e5968661", "Lily's Epic Quest"},
            {"aec0b087aaedda4ccd692b599d9637", "Mahjong Carnaval 2"},
            {"b2f9046b1a6aab154d62851e0a24f", "Mayan Prophecies: Ship of Spirits"},
            {"20dcb7dee3537b6d541e5c65c33631", "Monument Builders: Big Ben+Eiffel Tower"}, // error?
            {"c1049bd26003dc5b7495e73c5d87d9", "Monument Builders: Notre Dame"},
            {"2106d8bd2e4e82e897f63604a8668f", "Monument Builders: Titanic"},
            {"212704c2b50a1bba36f7a943e1cef9", "My Exotic Farm"},
            {"add0ce064162d9020768f1a047e4e1", "My Kingdom for the Princess 3"},
            {"b44007d0e47df134359235b3026ad", "Mystery Case Files: Escape from Ravenhearst"},
            {"b49590fd31b434a94264a0bdd79c9", "Mystery Case Files 9: Shadow Lake"},
            {"000203af91803e5f5e708c8dc8e94f61", "Namariel Legends: Iron Lord"},
            {"6e3dc31e6cb737257a5ee6e944125f", "New Yankee 3: In Santa's Service"},
            {"8a572ab7806d337a7d10df5beb37d1", "Oasis"},
            {"7e9597f0c730b861da813766624529", "Ominous Tales: The Forsaken Isle"},
            {"b351a4cbb6c324236332eb601fc35", "Order of the Rose"},
            {"b3a7a4a05510308a45a6914685a57", "Otherworld: Shades of Fall"},
            {"1478a99eebefcf3152cb6f139fea5b", "Pac-Man Pizza Parlor"},
            {"2b9fff4b3b6cb0f71a10df5e64a4ed", "Paranormal Crime Investigations: Brotherhood of the Crescent Snake"},
            {"47542c8e4db6dc560807c52de42dad", "Pirate's Solitaire"},
            {"87d0c88af7e2e4d5a7f9c7f5f14f49", "Planet Horse"},
            {"84bbdac860751c497f57b95ff2363", "Pop Voyage"},
            {"405437e535305de31074b0f59dc8f", "Pure Hidden"},
            {"6868e3881f563923768800f10efb7b", "Rainbow Web Bundle"},
            {"8d7cbf86b952153c86f632e21b5c8b", "Ranch Rush"},
            {"8de61398f11da2e8f82b8f49e8dcc9", "Ranch Rush 2: Sara's Island Experiment"},
            {"209a9a551df34ac73981e3cc77953", "Royal Envoy: Campaign for the Crown"},
            {"200876678a936592f9bbf9714bea9", "Royal Envoy 2"},
            {"2103b3644488cdfffb311e5c3647cf", "Secret Case: Paranormal Investigation"},
            {"f340714ff1085240351a004ddc3ab", "Shop it Up!"},
            {"b3d3aa06b4b09d25db1f11e73ac07", "Silent Nights: The Pianist"},
            {"8a4f838ed457cf4cd70b8ecb18ea17", "Soap Opera Dash"},
            {"bea51f31e96d40702b5dc70ce79e5", "Solitaire Egypt"},
            {"ae6f5d7bfbd1497f369e6779833c7d", "Solitaire Legend of the Pirates"},
            {"20dd58adc9754f5c0d23ee0c42b31", "Solitaire Mystery Double Pack"},
            {"b337771b6dc4014656792f6a2e5e3", "Stranded Dreamscapes: The Prisoner"},
            {"b45919c5b7276d24a2129aed6273f", "Surface: Reel Life"},
            {"b31ba5ff960d262ff6cbead55cfb9", "Surface: The Pantheon"},
            {"6b2e0e765982d9a65fff6410f0e4df", "Sweet Shop Rush"},
            {"59804f38b5ea9d5e50af0aeeb2377d", "The Chronicles of Noah's Ark"},
            {"2a6b7de19a682d882c91eacdeeaee7", "The Curse of the Werewolves"},
            {"119c1da1f18948117da51e403b01e3", "The Far Kingdoms"},
            {"1af533bcf25dfab8bac92f383e6063", "The Island: Castaway"},
            {"b2f49f4e25eea0aa0269ac12683bf", "The Keeper of Antiques: The Revived Book"},
            {"e76cff4e9b1ff17c17a932b0ade55", "The Others"},
            {"b3b2d676b61062ab4c0ad71b2adb3", "The Secret Order: New Horizon"},
            {"19fc90be212be495a29a7ef61930d5", "Grand Theft Auto III (GFWL)"},
            {"b30fa4012237aafe4b89483153811", "The Secret Order 3: Ancient Times"},
            {"b41c145ecb80cd0142c40b491f62f", "The Secret Order 4: Beyond Time"},
            {"b436a1b55e878f7c762fed2a4e45d", "The Secret Order 5: The Buried Kingdom"},
            {"b4989bb2c86ef3ae2983259184b87", "The Secret Order 6: Bloodline"},
            {"ece0f7061fe7b89f168ba17538349", "Grand Theft Auto: San Andreas (GFWL)"},
            {"20db88141fe69f6e0d61bcbd36724d", "The Three Little Pigs: Search and Find"},
            {"9d6c06ce14e6c95b779bb9ab7ba95", "Trinklit Supreme"},
            {"407fae113cc18cf8abeb23a15e3d07", "Tropical Fish Shop 2"},
            {"2b3b308b9c7fcb1078708ee9cd33af", "Village Quest"},
            {"6e7872da6c71a4cfca4884043e06ef", "Weather Lord"},
            {"8a5f8cecdba8ffdd32a0a0088bee6f", "Wedding Dash"},
            {"b312c16571f5f5500a75c8b845e73", "Witches' Legacy: Hunter and the Hunted"},
            {"20c5cb97c764e86ceefa2e03c1eb1", "World's Greatest Places Mahjong"},
            {"20edb9b154c02e0f9cb39f90df304b", "Yakari Wild Ride: Looking for Rainbow"},
            {"1a3053eba7596b15d419381d94343b", "Youda Camper"},
            {"1a7e258642df9e079a1a6b2ddb1f7d", "2025: Bitva za Rodiny (RUSSIA)"},
            {"53705a844664ee29730ea91d958425", "Grand Theft Auto: Vice City (GFWL)"},
            {"74f07c7a3e0d9e96d705cc36a8bacf", "Bionic Commando: Rearmed"},
            {"22ae47ace1b4cead410dd143a7914b", "Chessmaster XI: Grandmaster Edition"},
            {"2be857835caa760d0175838837e36f", "Ice Age: Dawn of the Dinosaurs"},
            {"f002a6ed893a0934a905470c75805", "Kane & Lynch: Dead Men"},
            {"8239c9fdb87ecc0990bbf036f4d72b", "NecroVision"},
            {"2196afa50491337971f443434e8551", "Neopets Puzzle Adventure"},
            {"14a8056098c93caf7aefe9ce65852b", "Prototype"},
            {"3d1d17729342838d8f08a22b888e11", "Sid Meier's Civilization IV: Colonization (Russian)"},
            {"60b16391ad542e4c2c867fea8a7239", "Sid Meier's Civilization IV: Colonization (American)"},
            {"2cf851e392b63539ab150ac3c2cad", "Alisa v strane chudes (RUSSIA)"},
            {"19435a286184c284c3cf0af8fce8ed", "English s kotom Leopoldom (RUSSIA)"},
            {"9b7e2107a2ed6255224c5bc424f285", "Byria v stakane: gonki na marshrutkax (RUSSIA)"},
            {"26b8a82aa3bfa5690095e838580a55", "Vozvrashenie mushketerov (RUSSIA)"},
            {"c14a24f51f638b3a3c8531c94f3a1", "Kot Leopold: priklycheniya v lesy (RUSSIA)"},
            {"19d89f5be5962d99c101f1351e7385", "Nochnoi smotryshiy (RUSSIA)"},
            {"9546b68515e4f978b8015f849e7ac5", "Kot Leopold: uchim Russkiy yazyk (RUSSIA)"},
            {"4b8d2fa78b201845d5563458d8dd6d", "Taina tretie planety: Alice i liloviy shar (RUSSIA)"},
            {"2d1a0b1d9605f124c939716597cc81", "Taras Bulba. Zaporizhzhya Sich"},
            {"c025b57dc370fb94f6f68604ce6fd", "Tri mushketera: sokrovisha kardinala Mazarini (RUSSIA)"},
            {"1a1e48c8b14f793d507aa381643a83", "Brain Training for Dummies"},
            {"10027d7f3c28cb975fc35c7835874b", "Egypt: The Prophecy Series, Part 1"},
            {"1005d0236cdb67676b331f0df33763", "Egypt: The Prophecy Series, Part 2"},
            {"100b627eb1971a8695cf759c0c35bf", "Egypt: The Prophecy Series, Part 3"},
            {"19a9196fd522bee9a6da11d1e8f85d", "The Fate of the Pharaoh"},
            {"6e13beef9d858c9d396b1bbc314027", "Hamlet"},
            {"6e0db8c20f643466637c3687414e81", "Natalie Brooks: Mystery at Hillcrest High"},
            {"6e0d3da1f31a7cf22fbccc5d37a88b", "Natalie Brooks: The Treasures of the Lost Kingdom"},
            {"b304a2e0e7118a7a0eb6d7eabf2cf", "Reincarnations: Awakening"},
            {"24d86e386eceb4784b35af1dafe34b", "Unsolved Mystery Club: Ancient Astronauts"},
            {"dc8820f06b23fbb96b07904deff39", "1912: Titanic Mystery"},
            {"6e295b08135a5dcb7c7075db7d6503", "Alabama Smith: Escape from Pompeii"},
            {"6e3221df0f77b39046f01527c9a923", "Alabama Smith in the Quest of Fate"},
            {"6e8aceac748d122c0e7ff516fd60cd", "Carl The Caveman"},
            {"b360531f73675685c693b4370ca65", "Cassandra's Journey: The Legacy of Nostradamus"},
            {"b400271ab50e5f8ca1b15b2acf4a5", "Chicken Chase"},
            {"b3aa12e760bc2ab81222245ddc1fd", "Haunted Hotel"},
            {"b30edd6138d186cdb7381163d7671", "Haunted Hotel II: Believe the Lies"},
            {"b3031a63ceac66a871fa4c346c0cd", "Haunted Hotel 3: Lonely Dream"},
            {"b490208c31963260d5c07375718fd", "Haunted Hotel 4: Charles Dexter Ward"},
            {"b3e2418fbbd920cba1e6eed40e6fd", "Haunted Hotel 5: Eclipse"},
            {"1c7bad0357b58da2c3c59c023b0499", "Heaven & Hell: Angelo's Quest"},
            {"8ab6213a2d77806865b41d721cd763", "Murder Island: Secret of Tantalus"},
            {"2ac4663681782e7e3fd762f3213fb3", "Nora Roberts: Vision in White"},
            {"d1d0f7fc567236bbd6c3892b29303", "Northern Tale"},
            {"6e14e70c84a293a1889f9509d3d191", "Oriental Dreams"},
            {"b47177870df526515e4c5cbbed5bb", "Shaolin Mystery: Tale of the Jade Dragon Staff"},
            {"6e2115e972436b57ff94d2b59fe9d5", "The Jolly Gang's Spooky Adventure"},
            {"20881691110ec71ac7084a6479672f", "Three Musketeers Secrets: Constance's Mission"},
            {"20d0b67dfb4ad3f0b30237718ea6c1", "XIII: Lost Identity"},
            {"16bb767c5896d23923e67d2d1dd021", "Chainz Galaxy"},
            {"6e268cd184bc1c06771047cfa505a7", "Cubozoid"},
            {"6e67dcdb0965a6b87cdb0ad2e68333", "Dig McDug"},
            {"837c45120c13069f93c555d12c081", "E.P.I.C.: Wishmaster Adventures"},
            {"c08dd75f5260c919cef6f86317878f", "Edna & Harvey: Harvey's New Eyes"},
            {"11028221f0fadfc179acf399dc0971", "Jewel Quest: The Sapphire Dragon"},
            {"b39a8276879cb7fb26efbb2f141d5", "Fetch"},
            {"b3aecbc3e29a7e82445dd37cce6cf", "Fish Tycoon"},
            {"8a87e0e3250b77e63bb2bd1608f27f", "Gotcha: Celebrity Secrets"},
            {"1afa07a05c893866c4321a54ff10dd", "Inca Ball"},
            {"ef132014290ba94c674f18a149313", "The Sims 3 70s, 80s, & 90s Stuff"},
            {"8136fa4f8119c20ef9f71667604b3", "The Sims 3: Into the Future"},
            {"932d4a06f5df4abab58d5f7d39ca69", "The Sims 3: Island Paradise"},
            {"a4ac35d85adf91f5219ec9c3d3a1f", "The Sims 3: Movie Stuff"},
            {"1e0ee9f28351e423dd7595347a2eb", "The Sims 3: University Life"},
            {"ae7747cf37a08bfd08dd91c395da0f", "Asian Riddles 4"},
            {"3a4111b884b5ceb035e534379dbca5", "Department 42: The Mystery of the Nine"},
            {"32408e810e5d15b362349507daac5f", "Elementals: The Magic Key"}, // why are there two
            {"6e0d7c958d9a429caa952807b29ae9", "Engineering: The Mystery of the Ancient Clock"},
            {"adf214df11b360be382230b1aa9b13", "Farm Craft 2"},
            {"16b90199c998218232aed3f83fa531", "Glowfish"},
            {"6e6a54ddd0aa69045b001c86e7468d", "Hyperballoid 2: Time Rider"},
            {"ad8ec3d771e0b7f43ee4ee5bed2933", "Magic Academy II"},
            {"24c682fedcc43dbdc85165b4c74b9f", "Mevo and the Grooveriders"},
            {"adc363c6cac94d2d3a6c5e6e71ec9f", "Mysteryville 2"},
            {"11304073095eda24fb9acef6b49397", "Passport to Paradise"},
            {"6e2f2c44a2c7b5ca9cd715e7135795", "Alice and the Magic Gardens"},
            {"8a706d8855f37cd5fb77498be32a75", "Alice's Tea Cup Madness"},
            {"1ab891febf619f22ddae0550956bcf", "Baby Blimp"},
            {"df582ab7cee0ac05866dd39cf13a1", "Babylonia"},
            {"20d0aafd6419f28f32a7a5716addd1", "Blake and Mortimer: The Curse of the Thirty Denarii"},
            {"4049fc1489da091b3244501fdce79", "Danger Next Door: Miss Teri Tale's Adventure"},
            {"6e1eb560a50e028fc2f03e473971ad", "Elias the Mighty"},
            {"b40c47ebd217d3b9c4bd33d25c527", "F.A.C.E.S."},
            {"6e690fbb2e324a545d035860797471", "Foxy Jumper 2"},
            {"5db289ffa798faad0e578e097deff5", "Gemaica"},
            {"5ff1d8e716613cf5f62f853c9e98f", "Madagascar: Escape 2 Africa"},
            {"6e513841f1d0329bd0013d51d99e95", "New Yankee in King Arthur's Court"},
            {"110ebf38066c81f6b19dabf33cb965", "Mall-a-Palooza"},
            {"6e0d8761de35230f50afcc0e4b84cf", "MOAI 4: Terra Incognita"},
            {"201a6fd58501e1b61652dfa31e0649", "Tropico 2: Pirate Cove"},
            {"2b52173e083560e514de977c6b1409", "Yeti Quest: Crazy Penguins"},
            {"356661598b8bc8803e1e318158673d", "Battlefield: Bad Company 2"},
            {"51be2ad562f419b46996da9f7fca23", "The Sims 2 (Double Deluxe)"},
            {"1e4fbbb610dfe023f523b634392ed", "Bone: Out from Boneville (DVD)"},
            {"1e4c994c22a8f838e09c00e2e2977", "Bone: The Great Cow Race (DVD)"},
            {"5010498a9b8630274a2e60d5e1a70f", "Harry Potter and the Half-Blood Prince"},
            {"902229a2a798a133be47acce475b17", "Overlord II (preview)"},
            {"629e6b64bebd399a4f1f184f76ea67", "The Club (Europe)"},
            {"12f70e9a0aacbb228dc31319b57325", "Turning Point: Fall of Liberty"},
            {"9175b54d3e8c83cdfc2095e43eb285", "Harry Potter and the Order of the Phoenix"},
            {"24c6f60a1385bef6c58466354bb9c3", "KetnetKick 2: Het Mysterieuze Eiland"},
            {"6e8261ba5f5002b010daaedf451629", "Manhunt"},
            {"d86738312a19caf3677824472e59d", "Grand Theft Auto: Vice City"},
            {"613713a56bcd9272281ff65a58b5f5", "Amber's Airline: High Hopes"},
            {"613d3ff126741b74de5b12e8bbe7ef", "Mortimer Beckett: Book of Gold"},
            {"213cb068629e04d2294a46d4fb8555", "2weistein: Das Geheimnis des roten Drachen"},
            {"1337b21d5a5e09cc76396919d2c957", "4 Elements"},
            {"1ae98438431d597716131e8ff2f277", "James Bond 007: Blood Stone"},
            {"75f50c6ab2b3526f7c8816ea5bd605", "12Riven: The Psi-Climinal of Integral"},
            {"b4488da658b3c4cf71fbe2e520c6f", "A Gnome's Home: The Great Crystal Crusade"},
            {"576d2d8c27cb033a01168b07befddf", "A Vampyre Story"},
            {"b3f9c7b6ec5adbe90138447dbbb31", "Abandoned: Chestnut Lodge Asylum"},
            {"adfd28e11279a6047c2746e8cf2bab", "Abigail and the Kingdom of Fairs"},
            {"89518e5ebf78b62d20a776c0c6897", "Agatha Christie: Evil Under the Sun"},
            {"6e7860bb407bde2ddffd8b9e00a649", "Age of Adventure: Playing the Hero"},
            {"f839e124d99fa1e08227204c340d9", "Alice in Wonderland (DVD)"},
            {"4c8eaa15b4f3d32a3fe5165720817", "Alter Ego"},
            {"1b1050669e927e53238cb5ec84ce85", "Ashes Cricket 2009"},
            {"181ff25b3212ba8b5ceb7abd63d295", "Avencast: Rise of the Mage"},
            {"98b17f87f433502ab3a9740b4c1241", "Battlefield 2142 - Deluxe Edition"},
            {"1ed554025ba10c9e22e2bffca31d71", "Battlestations: Pacific"},
            {"9cfead83c5a2efabfbb0d618d4fa4f", "Beijing 2008"},
            {"66bf09e1b262573589915e471827e1", "Bella Sara (CD)"},
            {"2e6d637d1f6184e6490693b3f0c7a3", "Big Buck Hunter: Shooter's Challenge"},
            {"b1762fbeb0d83acb080d5333cb3585", "BlackSite: Area 51"},
            {"2c54463920920713781795bf01acb", "Blue Blaster (Chinese Traditional) (DVD)"},
            {"84c3b3a463c7203800f0467973f8b3", "Broken Sword: The Shadow of the Templars (The Director's Cut)"},
            {"f3ca09ef8c7e4ea326022d2fd448b", "Brothers in Arms: Hell's Highway"},
            {"b47846dc951cb2c11df71da9ae7cb", "Cadenza: The Kiss of Death Collector's Edition"},
            {"b31713e8327a5017a1ab7efecca4b", "Calavera: Day of the Dead"},
            {"615abfe081001d2c31aec41854b50b", "Campfire Legends: The Babysitter"},
            {"6124f61ec530f10c61b431f158419f", "Campfire Legends 3: The Last Act"},
            {"2142773f7b0e840ab0013df554fcff", "Championship Manager 2008"},
            {"413d400c03637b6615359e83b0d51f", "Championship Manager 2010 (Europe)"},
            {"3bf78f59a1ec5c52d331c6dcaf45e9", "Championship Manager 2010 (Italy)"},
            {"2ac73bdd3f6d5d072405cd361b4da1", "Charlaine Harris: Dying for Daylight"},
            {"4154f9cee3c82619daae93bbf5d65", "Disney's Chicken Little: Ace in Action"},
            {"a43f4c4f0c4a10349af2be18bd169", "City Life 2008 Edition"},
            {"3ff5096953616fd1bd723bf238a2d", "Clive Barker's Jericho"},
            {"b40536ec0069a01d37623c8f17437", "Clockwork Tales: Of Glass and Ink"},
            {"4832049b469b0f93fe51b5b7fe6ad1", "Close to ~Inori no Oka~"},
            {"c197b48529ba3d14d8339208228389", "Colin McRae: Dirt 2"},
            {"18e6dc2178b03ddc7d8006079a4ca7", "Combat Mission: Shock Force 2"},
            {"62c21969caa4e5dc171908563a7db", "Crusaders: Thy Kingdom Come"},
            {"42f60d2d837fb9d1278a7d7b523e25", "Cryostasis: Sleep of Reason (Europe)"},
            {"98d6909cff465f16a854d66d18dd5", "Cryostasis: Sleep of Reason (RU)"},
            {"b343d4ed0d6d1e70b9d1146bd8459", "Danse Macabre: Crimson Cabaret "},
            {"b45bf857b3915b1e7cfcd2d9e7e57", "Danse Macabre: Deadly Deception "},
            {"b3551e3a161248579582c25078581", "Danse Macabre: Thin Ice"},
            {"b398cd1de89086c057640c6ea20eb", "Dark Canvas: Blood and Stone"},
            {"b32ff1fb55979e60285f3f5e18fc5", "Dark Cases: The Blood Ruby"},
            {"b3bedc93230b4b812c5a99eb9e5cd", "Dark Parables: Queen of Sands"},
            {"b2f2cb9f90b821b89c66c25ecc8cb", "Dark Parables: The Final Cinderella"},
            {"577bdd4cf09599a56035769a807817", "Darkest of Days"},
            {"b47a97d8cb2c63ae9dc7e1a477963", "Dead Reckoning: Brassfield Manor"},
            {"b3bf555dc43ee74cdd47d0f88cb2f", "Death Pages: Ghost Library"},
            {"60e06266c741787fbd84b9820a9d43", "Delicious 3: Emily's Tea Garden"},
            {"614f2994f46e3b6326c36e5e0a9477", "Delicious 4: Emily's Taste of Fame"},
            {"60f99f9ab92d75003c984713768ee7", "Delicious 5: Emily's Holiday Season"},
            {"61169d3b54c7dcbe33d8ff13a8ed95", "Delicious 6: Emily's Childhood Memories"},
            {"6128a10462345c7d04ecc124f9db43", "Delicious 7: Emily's True Love"},
            {"6111b91635e283c8fce33728d281e9", "Delicious 8: Emily's Wonder Wedding "},
            {"60e90d805739a039e0b1e7c6259d3f", "Delicious 9: Emily's Honeymoon Cruise"},
            {"61074b5f1d145e3eed5d3a56c1a2f1", "Delicious 10: Emily's New Beginning"},
            {"611b11d2e18a58dc43bca96caaa587", "Delicious 11: Emily's Home Sweet Home"},
            {"610ed4783b87d2f692eb43a1b42fc7", "Delicious 12: Emily's Hopes and Fears"},
            {"611169ad634518648f82d1cfa28f87", "Delicious 13: Emily's Message in a Bottle"},
            {"60f4d334f004cbd18f4ed889f8ca05", "Delicious 14: Emily's Christmas Carol"},
            {"6102b8435d8700358f5c37b02cee7d", "Delicious 15: Emily's Miracle of Life"},
            {"61393e015902337e8d1a69cd0f4bb1", "Delicious: Emily's Moms vs Dads"},
            {"54a67ffbd71f107de0252fb27ca329", "Dracula 3: The Path of the Dragon"},
            {"b34f2bc379af2081acef37b9778c5", "Dreampath: Guardian of the Forest"},
            {"b31163472fb02c8bb3638352abcf7", "Dreampath: The Two Kingdoms"},
            {"b472f94d38e6427b9b5bd243a03c9", "Dreampath 2: Curse of the Swamps"},
            {"6346b55da7acb2498a3ae9ceb5bc41", "Dreamwalker: Never Fall Asleep"},
            {"adad442cf8d0ee225b73b28b4df86d", "Druid Kingdom"},
            {"6e7ff2dc445f0cf33f2e6dac1c3d67", "Echoes of Sorrow"},
            {"b439b8e6cba6d5c988ebb9f9be5af", "Elixir of Immortality"},
            {"aebee1fa14d56a3bec8538653bfb59", "Elly's Cake Cafe (en)"},
            {"b3d3f959cc110ea0c35a1abf1fc1f", "Emberwing: Lost Legacy"},
            {"503d8e7951cbb91489d25aad64a965", "Empire Earth III (DVD)+(ru)"}, // error?
            {"7a37d88e158c02703a88f2ebe3285", "Empires & Dungeons 2: The Sultanate"},
            {"5a0284aa2438b0a332e2701c332a5f", "Escape from Paradise City"},
            {"d59922eaef29e7f6e922ad9d58b33b", "Everlight: Of Magic & Power"},
            {"e21dd5fdb35299260cf3ede068ea9", "Evil Pumpkin: The Lost Halloween"},
            {"2630480ecad7767850fe7b9d013b57", "F.E.A.R.: First Encounter Assault Recon (Extraction Point)"},
            {"58fc9eba7c459d5a01d3332d18c9af", "F.E.A.R.: First Encounter Assault Recon (Perseus Mandate)"},
            {"12f5630abd3525fa97e75e7f9732d9", "F1 2010"},
            {"61547f0a3501c1109bac419332f8bd", "Fabulous 2: Angela's Fashion Fever"},
            {"61437eb2ce4154bc49d4abdb5981d7", "Fabulous 3: Angela's High School Reunion"},
            {"614403575521c41a058671b6638c9f", "Fabulous 4: Angela's Wedding Disaster"},
            {"b46367900f2d55afb0ec6ef8c23a3", "Fairy Tale Mysteries 2: The Beanstalk"},
            {"b3a053b4249557d05fe3b5768d19d", "Fatal Passion: Art Prison+Haunted Halls: Nightmare Dwellers+Dark Strokes: The Legend of the Snow Kingdom (French)"}, // error?            {"e0fae66a4a294a2db0d5460d3ae2b", "Puzzle Quest 2"},
            {"4ff593d86aabf48141d52923de95f1", "Fate: The Traitor Soul"},
            {"b3e25d6decb20cf4e47834959d911", "Fear for Sale: Endless Voyage"},
            {"b384dba7c7ece77f924a772b9df1b", "Fearful Tales: Hansel and Gretel"},
            {"5982efdf78501448e72f21fa6b529", "Fiese Freunde: Die Rueckkehr des Top-Agenten"},
            {"4d2a03e2ddc9030dcf003edd9f1713", "FIFA 08"},
            {"1efa7a6da4cdd5bf9b3f8882c326b5", "FIFA 10"},
            {"3eda442f336a49dc05d71e0b2ef6e9", "FIFA Manager 07"},
            {"2ef5d7f4c6d0721db265eb3bfbcecd", "FIFA Manager 08"},
            {"226dad12609679a9a5608b125cb467", "FIFA Manager 10"},
            {"b389f7713e62bbc711db71ef15ea1", "Final Cut: Fame Fatale"},
            {"b477b8c785211b69c5b13021bf073", "Final Cut: The True Escapade"},
            {"718f69ef76ff8982196b717507fbfb", "FlatOut: Ultimate Carnage"},
            {"b364f6721411715c46423daf7b4a3", "Flights of Fancy: Two Doves"},
            {"1c516bb632bfc2b78f62be27b49b7f", "Football Manager 2008"},
            {"b3cfbcea9d689a8e54635f5523905", "Forgotten Books: The Enchanted Crown"},
            {"b3834f87e500532dd6e879285b87f", "Forgotten Kingdoms: Dream of Ruin"},
            {"19a5951efda98d76a90cabb73917a3", "Frogs vs. Storks"},
            {"cf1e0a9d6bb01069c6225623b2ee05", "Frontlines: Fuel of War"},
            {"355a55f20dba82a9dde5cc9b52737f", "Galactic Assault: Prisoner of Power"},
            {"b481ff132515cd829bbb6d5cdbe31", "Ghosts of the Past: Bones of Meadows Town"},
            {"ce5d508095b8500efeb4e795d9a9f", "Gingerbread Story"},
            {"aebab6c0d20f7c031cc6433988dc8b", "Gnumz 2: Arcane Power"},
            {"b3ed2613725ff24f08d836d2f23cb", "Gothic Fiction: Dark Saga"},
            {"b3275014115906296d20c4058d095", "Grim Facade: Hidden Sins"},
            {"b3b7cb4977bc443e850e8804147d7", "Grim Facade: The Artist and the Pretender"},
            {"b37e34befd409f3e82e7d541a4c8b", "Grim Tales: The Final Suspect"},
            {"1256f7d3b8bc8d3791ef051e0dfd47", "GTR Evolution"},
            {"157152f5b56ec17158affe036e83bd", "Guitar Hero: Aerosmith"},
            {"67d373b05ef78d76a2206495e15d7f", "Guitar Hero: World Tour"},
            {"9cff36baace085ccac1cbf64311549", "Guitar Hero III: Legends of Rock"},
            {"9462fc5d0cb5230c78da9b884c0823", "Hannah Montana: The Movie"},
            {"49e5d9151eadd78470335a691d99cf", "Harry Potter and the Deathly Hallows (Part 2)"},
            {"b3e46021e324d1b5b3ac3b3993ca9", "Haunted Legends: The Curse of Vox"},
            {"b36dbfabf449664591d838e73b95f", "Haunted Legends: The Dark Wishes"},
            {"b442f55960b55b64deba4eafcb5f5", "Haunted Train: Spirits of Charon"},
            {"615a845be1a17114a6345b3bb283eb", "Heart's Medicine: Hospital Heat"},
            {"b399bcd83d0a22abeab99266411bf", "Hidden Expedition: Smithsonian Castle"},
            {"b4872fa899febedd6b99efd34ad4d", "Hidden Expedition: Smithsonian Hope Diamond"},
            {"b4687fb41d8867fa062d769b6e2dd", "Hidden Expedition: The Crown of Solomon"},
            {"b4054f4d4c41916a9f12ceeea2fbb", "Hidden Mysteries: Gates of Graceland"},
            {"6336c489be9d032a6948b23a4a79f1", "Hiddenverse: Tale of Ariadna"},
            {"63b8c3aa872f6af7af0a7dcdfdee41", "Hiddenverse: The Iron Tower"},
            {"c439cd2f21565d2b81e738231dfac9", "Hired Guns: The Jagged Edge"},
            {"3881e69231b9a48c1aa3959214e7a5", "Hour of Victory"},
            {"2e16cff9e2558bf7ca8bc00b739c57", "Hugo: De Forste Tegn (sw)"},
            {"568b36dd53b2a4d55672dfea64c56d", "Hugo: Magic in the Trollwoods (dk)"},
            {"108c22199100088efa9cb8781e1679", "Hugo: Magic in the Trollwoods (sw)"},
            {"2b6c178d2a62601542294a56e9357", "Hunter's Trophy"},
            {"6e1dfe0ba6e0a6f90c214c31d262bd", "Huru Beach Party"},
            {"271c25ce6fffb86b8795e16b350ebb", "Ice Age 4: Continental Drift – Arctic Games"},
            {"e6d1985a47598a01b9e73404b8c48d", "IL-2 Sturmovik: 1946"},
            {"f2a984c435e35579206ddcb088a445", "International Cricket Captain 2008"},
            {"c286d34a3387d00ba7ad6963ffe1f", "International Cricket Captain 2009"},
            {"216f45d2fd415fbca80628ddb5bf7", "Iris (China)"},
            {"4daac5f844e2381038460df4dc60e1", "Iris (Taiwan)"},
            {"b6cd2614f8e880285fd3231d500081", "Ironclads: American Civil War"},
            {"2446c45168cc47eef8d4263ed97fd1", "Isla Dorada: Episode 1 - The Sands of Ephranis"},
            {"bc02ecec408e4b39364cb6f0b9ab5", "Jade Empire: Special Edition"},
            {"635e3990db8170daafa95b25da4765", "Jane Angel: Templar Mystery"},
            {"bcf0fa901e31ef9f795c2f474aca7", "Jo's Dream: Organic Coffee"},
            {"bd426c9efb3859110d3e78da1eee9", "Jo's Dream: Organic Coffee 2"},
            {"95f3590fdb5adca37f5ac2724341d", "John Woo Presents Stranglehold"},
            {"ea8d45e05c2d2ee88ff45fa55326d", "Juiced 2: Hot Import Nights"},
            {"b3c64b5c612acb2641d4a64c69e6f", "Kate Arrow: Deserted Wood"},
            {"33faf9eb7c8e0fe3b229412fc4e535", "King's Bounty: The Legend"},
            {"3da9fb0f23a7c4b6adda84c1e11581", "Lara Croft: Tomb Raider - Anniversary"},
            {"b2f7a9b5c6dc2e872729c60003315", "League of Light: Wicked Harvest"},
            {"b327d089c6c0b948d5089ea66d031", "Legends of the East: The Cobra's Eye"},
            {"1faeca4abbc7e4703b3331a4fc0149", "Lego Batman: The Videogame"},
            {"1ac0bdce39ed766c5eef5810f3861d", "Lego Batman 2: DC Super Heroes"},
            {"ac5fef0f8c3612606abce6b01e825", "LEGO Harry Potter: Years 1-4"},
            {"20f2d351864b54d5a3e288c16fd0a7", "LEGO Indiana Jones: The Original Adventures"},
            {"2c9e11eee91b385c45e1bad237aecb", "LEGO Indiana Jones 2: The Adventure Continues"},
            {"161e26bc0f3139311e937b69280bc3", "LEGO Star Wars: The Complete Saga"},
            {"5f1217dfbec9572b3ff08d5cf9db61", "LEGO The Lord of the Rings"},
            {"2d7951b24ecc3f35a9ea6272b62321", "Leisure Suit Larry: Box Office Bust"},
            {"20e86fc73d80571456c4471fe79013", "Les Miserables: Jean Valjean"},
            {"b377246994ccc594aeb2d64ab89d5", "Life Quest 2: Metropoville"},
            {"b3cde3766c7ec9e4b1b497ce4317d", "Living Legends: Frozen Beauty"},
            {"b3c0d7720c1bd01767dae771dcde9", "Living Legends: Wrath of the Beast"},
            {"1df918b13027b94049859c6c109dc7", "Longman Dictionary of Contemporary English (5th Edition)"},
            {"562b314873371a7595bd320505f723", "Lost Empire: Immortals"},
            {"b34e348f38176e3a1fde6da076055", "Lost Legends: The Weeping Woman"},
            {"a7a1bfb49a7225e6886866830fda57", "Lost Planet: Extreme Condition - Colonies Edition"},
            {"4cbff222a6d8326e254c692294eb81", "Lost Planet 2 (DVD)"},
            {"b451fd1a807f8929e633114340c2b", "Lost Tales: Forgotten Souls"},
            {"eec68031729c5d614a80401df196f", "Madden NFL 08"},
            {"b2f7b9a1695f4654cc7700283bd53", "Maestro: Dark Talent"},
            {"11123dde3a23c41ec1d12383e869b5", "Maggie's Movies: Second Shot"},
            {"7fa288eb0afd232098121d44295e05", "Marvel Trading Card Game"},
            {"53319f06d3ee8daead2e9c77a2b161", "Max Payne+Max Payne 2: The Fall of Max Payne"}, // error?
            {"b3f7c881abcac7528e621b1c01223", "Mayan Prophecies: Blood Moon"},
            {"17e2355efa92d67e7d1842210af20b", "Memories Off 6 (China)"},
            {"710723674320deb802bc63d9f192fd", "Men of War"},
            {"b38cad67fa6b41f6fa056a699bcad", "Midnight Mysteries: Witches of Abraham"},
            {"4f15190d13a1b79a8af50a6b5d5045", "Mini Ninjas"},
            {"51210699f7988e2bdac44c3f69f9c5", "Major League Baseball 2K09"},
            {"70e969c6dcd5e04fc70d435ed5463b", "Major League Baseball 2K11"},
            {"25392e1b3488a0bd0669e379774ea9", "Monkey Island: Special Edition Collection"},
            {"7e84b999410d41912dfcf8b5dd9945", "Monochrome"},
            {"60fbb5ed24ce69cff4f072c3654587", "Mortimer Beckett and the Crimson Thief"},
            {"614997d98c3b64440256f332ec915f", "Mortimer Beckett and the Time Paradox"},
            {"3c2ca59c070d237873e7f9508fa701", "MotoGP '07"},
            {"6e3384143ad040d591c11d23140f1f", "Motor Town: Soul of the Machine"},
            {"11dec4ac599f99d1ec98cc1d3b6d9b", "Mountain Bike Adrenaline"},
            {"5d467b32d4070e6c39bfa4cb19f059", "MySims"},
            {"b41ec0f0c03dcfb53ca367e96dd1d", "Mystery of the Ancients: Deadly Cold"},
            {"b2fa23674906e9acc76bcabc6347b", "Mystery of Unicorn: Castle The Beastmaster"},
            {"b44bd7c4ed940411adead90eae21b", "Mystery Trackers: Blackrow's Secret"},
            {"b4908f3159b2868f1629262978cc5", "Mystery Trackers: Silent Hollow"},
            {"b361f98aca6be73ea08b91e2f3e23", "Myths of the World: Black Rose"},
            {"28840b65e71ed150aaec7958f6840b", "NBA 2K11"},
            {"1fba19996affb33ef5ea3d341e609f", "NBA 2K12"},
            {"44f20ca47fffb435049c7363f19df", "NBA 2K13"},
            {"669a8f6488e9fce660990c2967b659", "NBA Live 08"},
            {"1250e81bc553a965ba5ce31f3aaf0b", "NecroVisioN (Europe)"},
            {"470b9e40ab7b7de9efce47eee2a8cf", "Need for Speed: Shift"},
            {"b334011bb168f97825d1c71033aa1", "Nevertales: Shattered Image"},
            {"b2fda5a418fdc43913a4409095215", "Nevertales: Smoke and Mirrors"},
            {"b37d754edbe98d83487698c4d0b4f", "Nevertales: The Beauty Within"},
            {"b3d3bdc97c7d57796ad667ea4710d", "New York Mysteries: Secrets of the Mafia"},
            {"202f045d851a43513994dc55163099", "NHL 08"},
            {"b448b6cce07046755fd456e0a10a5", "Nick Chase: A Detective Story"},
            {"b43bce1934153c74ee85bcf7e1a09", "Nick Chase and the Deadly Diamond"},
            {"b3063176c2a9d0bc360376e2c1b85", "Nightmares from the Deep: The Siren's Call"},
            {"60d4f8e33cc6a3312588e247f8ac85", "Ninja Blade"},
            {"6e67ab90577cdb172899af23ee0509", "Nonograms: Wolf's Stories"},
            {"d019c14a5ee8a0c5ed692d79292b3", "Northern Tale 2"},
            {"21169a420d1413758994347a11c8d3", "Occultus: Mediterranean Cabal"},
            {"6e26d643b13cab0654e0eada5483b3", "Oddly Enough: Pied Piper"},
            {"312eb9ef3ab2cf898c8910431bc29d", "Off Road (Ford Racing - Off Road)"},
            {"b4972e52522cb7accee14a8bea743", "Off the Record: Liberty Stone"},
            {"b3034547ae317df685e8e77e899f3", "Off the Record: Linden Shades"},
            {"b40ce71657f86a41451c880bf98bf", "Off the Record: The Art of Deception"},
            {"3a44f397bef040177046ee312a95d1", "Officers"},
            {"ac2d8123a51b7e34d0491c8adf8c1", "Operation Flashpoint: Dragon Rising"},
            {"b435930d8cceb47b73e67e3e0b7e5", "Order of the Light: The Deathly Artisan"},
            {"4a7e6b2dd9e6d0ad26b9579c0296ff", "Overclocked: A History of Violence"},
            {"26bbae6d2869098900bdfbb1af469b", "Overlord: Raising Hell"},
            {"45a13f001d7c96f9fa9364df861507", "Painkiller: Overdose"},
            {"fa5b8897c0885b853f507aefb9da9b", "Penumbra: Black Plague"},
            {"5d681d3cb75046663ffbefc5d3437", "Pro Evolution Soccer 2008"},
            {"18c07031630f4dd3fad043e7a37fd", "Pro Evolution Soccer 2009"},
            {"268f27f0c0fcd4bac247266ad30c6b", "Pro Evolution Soccer 2010"},
            {"120df6a558994f23a382b78cda2f8b", "Pro Evolution Soccer 2012"},
            {"3ba9d2cbca323ed0a30d8219ba559", "Pet Vet 3D: Animal Hospital Down Under"},
            {"b36b3eca74f0b991adbdfc99f90db", "Phantasmat: The Dread of Oakville"},
            {"b41f826919f371fe22c5d6aee49bf", "Phantasmat: The Endless Night"},
            {"b31a91aa190c58029891464e7af69", "Phenomenon: Outcome"},
            {"c32fc476c33c81f624dd47e856057", "Pipe Mania"},
            {"82017b3b6311c873d1a10351da509b", "Pony Friends 2 (DVD)"},
            {"7453575f5dd72669e8171f3a747913", "Power Rangers: Super Legends"},
            {"b36f438be18a6683d796b17a00d7d", "Private Eye: Greatest Unsolved Mysteries"},
            {"3075c048e35cc54088ff9b7372e4e1", "Project Fashion"},
            {"7afd72a97594562d317fcfdd04003d", "Project Runway"},
            {"b3091e0197c6b7220b2b5be1d3693", "PuppetShow 5: Destiny Undone"},
            {"b2ebe10f8845c13de794f8cf2a44f", "PuppetShow 6: Lightning Strikes"},
            {"b41c6537b1bf66c9f09307f8d8283", "PuppetShow 7: The Price of Immortality"},
            {"56ff3e1594bc5fe0a1448bdb92a27f", "Pure"},
            {"b2f49db3af9e8e7ad24e3f5d9e303", "Queen's Tales: Sins of the Past"},
            {"b494bfe794dc0b82f88235ff7933b", "Queen's Tales: The Beast and the Nightingale"},
            {"169885bbb07b6f09daa6340beb2015", "Race On Bundle (Race 07+STCC+WTCC '08 & US Muscle)"},
            {"7bd862424b855ff09f53c25dc57af", "Rail Simulator"},
            {"1341d5bd990291ebff5d716e47ef23", "Raven Squad: Operation Hidden Dagger"},
            {"b3f5e03ddbb58482817d124e852a5", "Redemption Cemetery: Salvation of the Lost"},
            {"b3f07acda3d0546251ef6a4060625", "Redemption Cemetery 5: Bitter Frost"},
            {"b301f7cb3515db352b34b3141fee7", "Redemption Cemetery 6: The Island of the Lost"},
            {"564104f6321e21f07694e8fb6619a3", "Resident Evil 4"},
            {"b3b2d9ea7bb9c1d0d4a1d6b1df16b", "Reveries: Sisterly Love"},
            {"b4292d34de9dd6cd26dbe6dbe9f2b", "Reveries 2: Soul Collector"},
            {"b2fc07e6c8906b2a92948844cd3dd", "Riddles of Fate: Wild Hunt"},
            {"b389ea484aeaafbf7a0bf5fb56477", "Riddles of Fate 2: Into Oblivion"},
            {"b41c393a547da56330fd0efd002bb", "Riddles of Fate 3: Memento Mori"},
            {"69180e97a3327aedc9cd10b245b943", "Rise of the Argonauts (DVD)"},
            {"6e6dee03f5e101ef762048563efb91", "Risen Dragons"},
            {"b34aad4c8c1770a195d2e2d358d17", "Rite of Passage 3: Hide and Seek"},
            {"b319c23b8b3b860fe28a8c7b30ea1", "Rite of Passage 4: The Lost Tides"},
            {"b2fc9c9adafbe65979418a90a9aa3", "Robinson Crusoe and the Cursed Pirates"},
            {"3da0c2907540243e770b682a426613", "Rogue Warrior (DVD)"},
            {"3595869e27a03be1f1d8660ed7b0d7", "Runaway: A Twist of Fate"},
            {"1141d8ccec3be252a5c1e0984eb659", "S.T.A.L.K.E.R.: Call of Pripyat"},
            {"b40d79e2ccf660f175062f7f6b479", "Sable Maze: Norwich Caves"},
            {"60da4a37f87def522da3b9d020bae9", "Sally's Salon: Kiss & Make-Up"},
            {"16bfdf29206c3af65e2461a635ffef", "Samantha Swift and the Fountains of Fate"},
            {"1a5ed755f2f001561fdcc6e7aa1efd", "Samantha Swift: Mystery From Atlantis"},
            {"2d330f7d77941b77a1a4485edeac75", "Saw"},
            {"a350aa9646431b85def2d4092e787", "Scene It? Twilight"},
            {"1723b0abd31fdc0e8d0b328e97c1f7", "Scorpion: Disfigured"},
            {"b429f92d8618e6f92d4df477e2169", "Sea of Lies: Mutiny of the Heart"},
            {"b3e48f87fa812730652cb03fe9aad", "Sea of Lies 2: Nemesis"},
            {"b3a39217da5ee2e48fd41e5cc522b", "Secrets of the Dark: The Flower of Shadow"},
            {"a9a84f94563e4900745ff87bb0bd1", "Section 8: Prejudice"},
            {"56c338910d6a33bfd900d410c6bc07", "Separate Hearts"},
            {"b48b52a765ad797b08289ff4316ff", "Shadow Wolf Mysteries: Tracks of Terror"},
            {"b390ebd57a380a80c46550561daad", "Shadow Wolf Mysteries 4: Under the Crimson Moon"},
            {"20163150ed4c7dfd7680577d898f6d", "Sherlock Holmes: The Awakened"},
            {"b1b6d974d3f49df54658e99f0f653", "Sherlock Holmes versus Arsene Lupin (Sherlock Holmes - Nemesis)"},
            {"b3c9a9c1874d40585f9cae1f21d3d", "Shiver: Moonlit Grove"},
            {"b44d298ed139aef8457d8ea8261cd", "Shiver: The Lily's Requiem"},
            {"a05e82342d1bfc3468b2be16ad2cdb", "Shrek Forever After (Italy)"},
            {"b3114f74f6968173a372dbba63f31", "Shrouded Tales: The Spellbound Land"},
            {"90126759015146b4807be7f9457939", "Silent Hunter 4: Wolves of the Pacific (China)"},
            {"b36056727f6ca802df70de7ec3a69", "Silent Nights: Children's Orchestra"},
            {"107b1b66e4ce752e7aa9cdc3e33471", "SimCity Societies: Destinations (Taiwan)"},
            {"f7c57a3bd4dccd03024fefaeca819", "SimCity Societies"},
            {"4818fa143924078f0fd5c65d481145", "Singularity"},
            {"5cc0f292e773e2f93c4809d7e3b32f", "Skylanders: Spyro's Adventure"},
            {"b4728d1cc17a63ddf26d0170268c1", "Small Town Terrors: Galdor's Bluff"},
            {"b39c60c0bfaf046d2f7068e5c809d", "Small Town Terrors: Pilgrim's Hook"},
            {"832c3a954dd2bba1e4702e4c26adb5", "Speakout Intermediate Students' Book with ActiveBook"},
            {"1b037d43ce1659b3c5eb39ee2a544d", "Speakout Pre-Intermediate Students' Book with ActiveBook"},
            {"b498d570bf57e5ec61c5844e77e1f", "Spirit of Revenge: Cursed Castle"},
            {"564a5c7b896b1bd026bef8680610e1", "Star Wars: The Clone Wars - Republic Heroes"},
            {"dc0ae8e0657b02b0e92ef2cc748c9", "Star Wars: The Force Unleashed - Ultimate Sith Edition"},
            {"3b0da25c7848651602b94a0e31119f", "Star Wolves 3: Civil War"},
            {"9d41918097240a82b9b09a42608f63", "STCC: The Game"},
            {"117c8307ba46c8547c8ab5de4bd665", "Steel Armor: Blaze of War"},
            {"b410d4510556cf9cdfa224ceeb5c9", "Steve the Sheriff 2: The Case of the Missing Thing"},
            {"b41b5b7f764a5720a6e869dfad1d9", "Strange Cases: The Faces of Vengeance"},
            {"b3f63e483a114062d86c1cea1d20d", "Strange Discoveries: Aurora Peak"},
            {"b98665f8daa6d3b1ffbc5b58d7541", "Street Fighter IV"},
            {"13b4ce0fde8590a4f32b247a7d48bd", "Stronghold (CD)"},
            {"cdd43b9e030ed5f5bc3133cbcd4be7", "Stronghold: Crusader Extreme"},
            {"433b5ada47d397a173c0641b37bdad", "Supreme Commander: Forged Alliance"},
            {"5c09781bbd74c389fe90cf90f97607", "Surf's Up (Europe) (DVD)"},
            {"115c72ea08a86f7ebe3e36388fce23", "Surf's Up (Polish)"},
            {"b37c969e6fcbccd852933127767ed", "Surface: Alone in the Mist"},
            {"732d766015073f503b3c4782a70c07", "Swashbucklers: Blue vs. Grey"},
            {"b36bc7a7706549e4b86b8e269ceff", "Tales of Terror: House on the Hill"},
            {"79ebdaea4751ea94b1d753b40f9acd", "Tarr Chronicles: Sign of Ghosts"},
            {"15267ae22f2228fe1574b50da980d1", "Teenage Mutant Ninja Turtles"},
            {"4c1a84c0712795876d38bef99690ed", "Terminator Salvation"},
            {"3b456cecd30e980c8d23d7445218eb", "Test Drive Unlimited"},
            {"95e97642beced5aac1503aefa1c53", "The Abbey (Murder in the Abbey)"},
            {"1d2a19f555edb63d38ffaca693ddcd", "The Beast of Lycan Isle"},
            {"48f4ac3de32f9f9b8557ebec64546b", "The Book of Unwritten Tales: The Critter Chronicles"},
            {"82d8c82084c48198ff07bbbc546ff7", "The Book of Unwritten Tales"},
            {"169ba3837056d85cdb49e076ec8bcd", "The Chronicles of Narnia: Prince Caspian"},
            {"8540dfe8b57b4bb233ced7b3ef9ef", "The Dark Eye: Drakensang - Phileasson's Secret"},
            {"291be4e259be329e6e330e167b0b63", "The Fate of Hellas"},
            {"14a63dfa5dddf61a4286d656ef9e47", "The Golden Horde"},
            {"612ce3ef2c7f88eceb67af5e58a699", "The Love Boat"},
            {"d2e93bd0dd4cebc41b3e57d7d57f35", "The Princess and The Frog"},
            {"2167f57fe2ef0241612956afdd9721", "The Saboteur"},
            {"b43a1012aa137b7d0c38ebd7ebaab", "The Secrets of Arcelia Island"},
            {"894d28d9ac821659e55ab7a65504b", "The Settlers: Rise of Cultures"},
            {"225e2f2bbc82ec992766830b57ab0b", "The Sims 2: Apartment Life"},
            {"ba6c8d6edee3e267aaaabfbb8344b", "The Sims 2: Bon Voyage"},
            {"2ef97759ec93b57d97d3034bf7670f", "The Sims 2: FreeTime"},
            {"251f4cb68c5f51da58cb6e76772c11", "The Sims 2: H&M Fashion Stuff"},
            {"315367ebc63fa1659d6175ca4f102d", "The Sims 2: IKEA Home Stuff"},
            {"1362c942166c908ffffeb5f8a19507", "The Sims 2: Kitchen & Bath Interior Design Stuff (Taiwan)"},
            {"13db59ecddf905be7894f0dce6a1f1", "The Sims 2: Mansion & Garden Stuff"},
            {"500b6206af8472568f0c1547ab295b", "The Sims 2: Pet Stories"},
            {"5023217dca666de1b4aa8b5acc6321", "The Sims 2: Teen Style Stuff"},
            {"31546634d2b7f12f2bfc5e351c7737", "The Sims Carnival: BumperBlast"},
            {"4178d3508c4883f896c5cd8b11095", "The Sims Carnival: SnapCity"},
            {"29d6186e01eaa9ef0e2dd87a895657", "The Sims Castaway Stories"},
            {"5cfcd9fae575385f10b0ad7701e6d", "The Spiderwick Chronicles"},
            {"b4323648b08fe8d483796d20ba739", "The Torment of Mont Triste"},
            {"a917420ecf0eeaa5295575f9f7a655", "The Westerner 2: Fenimore Fillmore's Revenge"},
            {"8206a8193769485f491a0e2cda1b41", "Thrillville: Off the Rails"},
            {"1f2e8bdcaf4d71a16f92383dd37721", "Tiger Woods PGA Tour 08"},
            {"6994709ae1dfd649bc1fc0fa8ae93d", "TimeShift (Russian) (DVD)"},
            {"f53668db5c69e0cec26700140dde7", "Tiny Token Empires"},
            {"1fc1d843a522ecd0fca4815edf7f19", "Tom Clancy’s Rainbow Six: Vegas"},
            {"1449ead5479faf89078cc47cc86e59", "Tom Clancy's Splinter Cell: Double Agent"},
            {"65a5d373a9769bb54f7514e8964c3f", "Top Gun: Hard Lock"},
            {"1e6f90fe5dbc5207f96f4118d4e553", "Top Trumps: Doctor Who"},
            {"3129dde904194e082fbd8473035a15", "Toy Story Mania!"},
            {"4a72dd4b0eb6ee4de04d128cb4195", "Transformers: War for Cybertron"},
            {"31eaaf3e588da9c309cc190633795f", "Transformers: Revenge of the Fallen"},
            {"6ea684dfe1ebcf6aa0adffea22e1ed", "Trine"},
            {"31c311500f5b42bf22cfa221d38b77", "Turok"},
            {"879e58e738ff259b24e05d51a0e8dd", "TV Manager 2"},
            {"b481c9b74a8bbf2ad9cd0a255c1b9", "Twilight Phenomena: The Incredible Show"},
            {"b2f3eaa0cc7882c33f088ddd1d9e5", "Twilight Phenomena: Strange Menagerie"},
            {"a0788bf4f88ae1179d73447fe71bbf", "UEFA Euro 2008: Austria-Switzerland"},
            {"b3c309bf8ce16be2127e38d574235", "Untold History: Descendant of the Sun"},
            {"b394225b42fdcbe771ec1587ccb33", "Vampire Legends: The True Story of Kisilova"},
            {"18d9c31b6fa2747e22c004f0cd372d", "Virtua Tennis 2009"},
            {"1422300b0a4378a34cffad38f963eb", "Wanted: Weapons of Fate"},
            {"a1e32dda807254ec0012ef478f29d", "War Leaders: Clash of Nations"},
            {"5c6469093e71f93c9f64369ecc0837", "Warhammer 40,000: Dawn of War – Soulstorm"},
            {"359c27d126831eed5558ed0244c1b", "Wheelman"},
            {"b35ff5142bf5841f9b190507b26eb", "Whispered Secrets: Into the Wind"},
            {"7d26cc8ebffdf907a08762a706997b", "Wind Fantasy 6 (China)"},
            {"b44e5f62476e675622ad062e8a16d", "Witch Hunters: Full Moon Ceremony"},
            {"b4549f306c109126e2366cc558375", "Witches' Legacy: Lair of the Witch Queen"},
            {"b4677c605bd181ccceb83bd825153", "Witches' Legacy: The Ties That Bind"},
            {"b3b76dc7f3b22ca6b630cc03f7683", "Witches' Legacy 5: Slumbering Darkness"},
            {"f40da4d15d4fffa8e554db1dd174f", "World in Conflict"},
            {"60f4e3cd1caf8137968dc657b4589b", "Subway Simulator: Volume 1 - The Path: New York Underground"},
            {"b37938d5fa8ca2d9ab5d9111e3a9d", "Written Legends: Nightmare at Sea"},
            {"59a16cad6a22b9987fd61b86bf4633", "X-Men Origins: Wolverine (Uncaged Edition)"},
            {"2de2801ffbc8812b05f54f633dc02f", "Yesterday"},
            {"f3499972085a4b439c017fac1ceff", "Alicia Griffith: Lakeside Murder"},
            {"234efa3833ff8ac27c56d9a32b7c9", "All My Gods"},
            {"b3a9b0d74c0c02f10c412a40cc7c7", "Allora and the Broken Portal"},
            {"6e3a9d13ae91d894b1f00603ad4849", "Among the Heavens"},
            {"59bd0f028f2a88505f8a665d2ac3e1", "Artifact Hunter: The Lost Prophecy"},
            {"b2fc77d48c4c0c01422a18ada8ab9", "Beyond: Star Descendant"},
            {"20e9dce8c84713ca7e40dec8979627", "Black Viper: Sophia's Fate"},
            {"b4568c7ef4d5281b2c2d9e9f51295", "Bluebeard's Castle: Son of the Heartless"},
            {"b36107eb5975ee8e2501da26ac15d", "Busy Bea's Halftime Hustle"},
            {"d97e56c7bedc06d895e7d603feaad", "Captain Space Bunny"},
            {"c53193efe46e81a6736efe4873e2f7", "Cases Of Stolen Beauty"},
            {"ab5e25cf21c1666bae4f4ce8e8a0a9", "Cross Worlds: The Flying City"},
            {"e68c8d5de7ef77a9247c6f632efd1", "Dead Hungry Diner"},
            {"121e0f441fa7c2cc52d16c4a96a5b5", "Dead Rising 2"},
            {"2a8bb303b262afeab40c865dda413d", "Deadtime Stories (en) (digital) (Boonty)"},
            {"b405fab6eded5a1c8c603ea65e559", "Donna Brave: And the Strangler of Paris"},
            {"d058485ff66913eb74f70a324f5871", "Enigmatis: The Ghosts of Maple Creek"},
            {"b40c80dcdacbb6ee6153413b7a3c9", "Fantastic Creations: House of Brass"},
            {"6e3987c711dfe04c08c89c4d859cab", "Grandmaster Chess: Tournament"},
            {"b3901dc753a7c089276c3d378e7a7", "Guardians of Beyond: Witchville Walkthrough"},
            {"2b2ef877cac5dae76cf229057d4149", "Hitman: Blood Money "},
            {"e1ea2f93b9ea848f400027777c751", "Inbetween Land"},
            {"6e0eb3e445354c67df524bf8141e7f", "Incredible Dracula IV: Games Of Gods"},
            {"21102499552a1b1e63e915f80da839", "Jennifer Wolf and the Mayan Relics"},
            {"b31f3b442e673c183946d147eef13", "Journey to the Heart of Gaia"},
            {"20ec1a36532cce8ca6f7aef7ce3685", "Lucky Luke Shoot & Hit "},
            {"212021a24dfe25382744b00c87722b", "Lucky Luke: Transcontinental Railroad"},
            {"244026333128694786821e2481d8e5", "Mark and Mandi Love Story"},
            {"1003b5f5277711b9d59c8d27a53861", "Nostradamus: The Last Prophecy (Part 1)"},
            {"10092f37c81a8bb68efd4704ae1a91", "Nostradamus: The Last Prophecy (Part 2)"},
            {"100ae813f4c3e5b323f07895b11b5b", "Nostradamus: The Last Prophecy (Part 3)"},
            {"40820a8a7ae89381789b44e176c9b3", "Odysseus: Long Way Home"},
            {"1b8a9d883e2feb15b253fd8fafb3cd", "BMW R1250GS Repair Manual K50/12 K51/11"},
            {"6fbc97dd766a023d8f0732a9746955", "Disney Sing It"},
            {"387e72dc8f09e61601399016785dbb", "Silke, Pixelines Lillesøster: Kan du klokken?"},
            {"8c815594089c6086c327e12cf02fe3", "Sublustrum (Outcry - Die Dämmerung)"},
            {"91b04ce337ea3c706f7d65b9b91c3", "The Princess and The Frog (Scandinavia)"},
            {"57daab6b61a1fb7b8cf706840471e3", "Conspiracies II: Lethal Networks"},
            {"c100fb75dae61de312ac2fee5ebc61", "9 Elefants"},
            {"6e113ae1990ad434c32eb700b46e7d", "A Magnetic Adventure"},
            {"b48334bfa7e53a4b64f62f490ea85", "Abra Academy 2: Returning Cast"},
            {"cbe02f9615b91c93859a6c6a5ceb5", "Age of Japan 2"},
            {"206647aaed5387356c4fd41e1b541", "Alexander the Great: Secrets of Power"},
            {"52a405f31d387bd75d32e808e3289f", "Alice Greenfingers 2"},
            {"20d1c7c8b4f1d8644a1093fcb1bf9", "Alice's Magical Mahjong"},
            {"b3efc83c5883657f8a5674416813b", "Amaranthine Voyage: Legacy of the Guardians"},
            {"b43aad80083233ff5d4e5fae9139d", "Amaranthine Voyage: The Burning Sky"},
            {"b45f2906d96b82d644ef5e43cdb85", "Amaranthine Voyage: The Orb of Purity"},
            {"b315126900ed2d45ef20058fb6b6f", "Amaranthine Voyage: The Tree of Life"},
            {"b2f47b6bc07becde8794944c022cd", "Amaranthine Voyage: Winter Neverending"},
            {"fa77e5c3f06f287cf2da1a75171ef", "Ancient Spirits: Columbus' Legacy"},
            {"adc39f65214626f7e67fd998c457a7", "Annabel"},
            {"6e10df6e816cf0523894c6d5b0f449", "Arxon"},
            {"b42131419bec92ca4b022b610c52b", "Atlantis Sky Patrol"},
            {"b612d25e9cd51b166d8b04492dad07", "Bad Girl: Born to Run+Ballad of Solar"},// error?
            {"b3597bb4146651cb100ca6fa9777b", "Beetle Junior"},
            {"6886469f401a3358b26c06e5bcff07", "Bella Design"},
            {"189d0a37a046fdbc188bea5b6a7cfb", "Big Kahuna Reef 3"},
            {"19a479ab69ee2b06f3927af9849693", "Black Rainbow"},
            {"b3352fa32a1dd72033203117c959b", "Botanica: Earthbound"},
            {"152573138d2372641a92bda6f0f7eb", "Boutique Boulevard"},
            {"b31d531a408aea234341ad41fb197", "Bridge to Another World: Alice in Shadowland"},
            {"b35a55c0279b25931895bf2197d4d", "Bridge to Another World"},
            {"b438d5ff4042fc61c98001d8243f1", "Bridge to Another World: Escape from Oz"},
            {"e9ccb5cc912cdcce92e95020b3b47", "Bubble Bonanza"},
            {"2bbc7f9d54560b33791435d89b4963", "Burger Island"},
            {"b4077ea1b7b344683901f308aa8d9", "Cadenza: Fame, Theft and Murder"},
            {"b320484d04786ee43ecedebc0f911", "Cadenza: Havana Nights"},
            {"1da398da491c68500ab9ee3b2d36eb", "Cardboard Castle"},
            {"7e5f5b5b3bcb560b8b5c83e8c6bff3", "Caribbean Jewel"},
            {"6e14a10699cd9ae7e0887f78ace2cb", "Caribbean Riddle"},
            {"1ce43bfd2521625af81e038643a931", "Celtic Lore: Sidhe Hills"},
            {"7e668f3bc69ad173a01019cda4ae99", "Chateau Garden"},
            {"b3d2d57991e5382ccbc99ba08e167", "Chimeras: Blinding Love"},
            {"b2f5c52f6965550941ae653f939e7", "Chimeras: Cursed and Forgotten"},
            {"b31d3b3300607616af97726e18265", "Chimeras: Mark of Death"},
            {"b36b39b2ced56be13dc7dbdbf57fb", "Chimeras: Mortal Medicine"},
            {"b368317aa8e53716b967bc8e2cd63", "Chimeras: The Signs of Prophecy"},
            {"b3181497f8be07cc5d9aaadfb7d2f", "Chimeras: Tune of Revenge"},
            {"1527f6e9f189eb2667018236758781", "Chloe's Dream Resort"},
            {"b47808c2516dbe42d3d5f805cde35", "Christmas Eve: Midnight's Call"},
            {"7e41820f7dcc34a7c12efe033cc9bf", "City of Fools"},
            {"b4992f6b7c1d59284ab9ccb1dc19f", "Clairvoyant: The Magician Mystery"},
            {"3d3b2b274370819b3797c46e208d85", "Columbus: Ghost of the Mystery Stone"},
            {"e8d57a8c0710b085467ca50f8263f", "Crazy Belts"},
            {"11b07daa73e51aa8ee80945e545837", "Criminal Minds"},
            {"6e130a389d756af5ef2e8e773fcbd9", "Crop Busters"},
            {"6e26bc18c725b9e544c9ec71869d1d", "Cruel Games: Red Riding Hood"},
            {"e79c0867689ef5a6df4e058cb0bf3", "Crystals of Time"},
            {"b39ed2f2e7deba981ad99bf51326d", "Cursed Memories: The Secret of Agony Creek"},
            {"8ac0e9925a3517005d226157e7df2f", "Dairy Dash"},
            {"6e5a57d1b175cc09657a21ad8ca4fb", "Dancing Craze"},
            {"b331467ca3475f678130d600718c3", "Dark Alleys: Penumbra Motel"},
            {"b3a4c19c9ae44099ffb5a30d0f8cb", "Dark City: London"},
            {"b33ac69181b1887463d12cd2721c7", "Dark Ritual"},
            {"b33cae840c45923026c41bb26558f", "Dead Reckoning: Broadbeach Cove"},
            {"b377fa7b17938ef160ae5b7c6d503", "Dead Reckoning: Death Between the Lines"},
            {"b4828976ed3dd6bd002fb245fa1c3", "Dead Reckoning: Sleight of Murder"},
            {"b34300015a5da6925f24cb75d5d73", "Dead Reckoning: Snowbird's Creek"},
            {"b2fea7f1e8ea30d235954a8688883", "Dead Reckoning: The Crescent Case"},
            {"35f9216aeadfae49bf3ae574831915", "Deco Fever"},
            {"caa52129157efca5db9a29cf20a53", "Demigods"},
            {"b39271179fb0fe5f64daff2cfa0e7", "Depths of Betrayal"},
            {"ad59a25314cd5d01a227354300a089", "Detective Stories: Hollywood"},
            {"1bff860c05fe7c576a9b0bae5d8413", "Doki Jardim: Quando eu crescer!+Doki Primeiros Passos: Aprendendo no fundo do mar"}, // error?
            {"b38b5746fba7ec17680d4de93daf1", "Doors of the Mind: Inner Mysteries"},
            {"e7a6a2e39a5c5645d49c8302348ef", "Dr. Mal: Practice of Horror"},
            {"1132c961fecb4a60916c025c0f2f73", "Dream Inn: Driftwood"},
            {"4086a2f9e5d6cff11bc29286944dd", "Eden's Quest: The Hunt for Akua+Emma and the Inventor"}, // error?
            {"7e356668860d0290dc450f9763ec63", "Entwined: Strings of Deception"},
            {"adcba62feea1ee1c3dcfe1d766d4a5", "Escape from Lost Island"},
            {"3c53efa29b17becf33540757098ac1", "Nat Geo Explorer: Contraband Mystery"},
            {"1a4aa2594019d2f6930ede1f8b9823", "Fable of Dwarfs"},
            {"b35c345e7f3666c064714fa8085d3", "Fallen: The Flowers of Evil"},
            {"e22ebd10dce11aa996783b5b2e803", "Farmington Tales 2: Winter Crop"},
            {"6e4236277626cb79d2f6e680707537", "Fashion Season"},
            {"6e40f355f7ae427ca438b9bafde81d", "Feelers"},
            {"ae997a48acb19a851301429150dfc9", "Fill and Cross 2: Trick or Treat!"},
            {"6e2d561590075f17b467d03a6e2363", "Finders"},
            {"153949492f57791c3539ea9986891d", "FishCo"},
            {"1524bd6c86fcd29ca292b67d76813b", "Flower Paradise"},
            {"6e5c6ddda54f32bd4e8b6d40a6c767", "Flowery Vale"},
            {"23b74004eb2f208488d0a92f0c41f3", "Football Manager 2008 (Europe, DVD)"},
            {"6e1341adf6245b4f6aef01f49d6d75", "Forbidden Secrets: Alien Town"},
            {"e2d1a51c2d2c4889abf64814522c7", "Forgotten Tales: Day of the Dead"},
            {"4a6f86281987d95cde452fae68a6b", "Frankenstein: Master of Death"},
            {"b3f2ff43c4917eb1c1b7339bac26d", "Fright Chasers: Dark Exposure"},
            {"5e35000628543d409ee0ef693ec669", "Frozen Kingdom"},
            {"11c1374738915f65fb9fa47bfdd475", "Ghost Whisperer: Shadowlands"},
            {"6e7dcd13c56014c6638317bba2adb3", "Grace's Quest: To Catch An Art Thief"},
            {"7e3353b2a60ae531a2008fa4904481", "Greed: The Mad Scientist"},
            {"7e24b3b8825308e34b5a34e5e4e1fb", "Greed 2: Forbidden Experiments"},
            {"e1c03ed4c070d124b5370d41a5599", "Green Ranch"},
            {"b31971eae13cea9df2eb4d90b3735", "Haunted Train: Clashing Worlds"},
            {"b4949235c7df377c786da1ce013a3", "Herofy"},
            {"1145578fc1aada7365ba60de2c570f", "Hexus"},
            {"334d24695547032a4eb5251d434057", "Hidden in Time: Looking Glass Lane"},
            {"b2eb96821dcb29295a9401e12b107", "Hidden in Time: Mirror Mirror"},
            {"212057b5d2d55a2845cba134a82cf9", "Hidden Path of Faery"},
            {"6e79a3b04b849a46944e3ddec3a32d", "Holly: A Christmas Tale"},
            {"2b55eec63c302b10535f1114d3b2b", "Hollywood Files: Deadly Intrigues"},
            {"1aa20437c7190fb1d724b6622b6015", "Hometown Poker Hero"},
            {"ad5a62a198d05b7b85bfdb61fa71cb", "Hypnosis"},
            {"6e2525ce395567f249a711d3d2adeb", "Ice Puzzle Deluxe"},
            {"7e2b6fe493bacb21c0a72c4935d26f", "Intrigue Inc: Raven's Flight 1.5"},
            {"b2ec46e0ae7767b7a1dbca5433e5f", "Island: The Lost Medallion"},
            {"906ff3c5fdb24af94c9e6ba7b862f", "Jack of All Tribes"},
            {"6e0d3ff3a9ee486ac1540131a78eef", "Jenny's Fish Shop"},
            {"6e652c5408d493ce9497faa05cf1f7", "Juliette's Fashion Empire"},
            {"aec58aed6f5fc6515b6e4ff28f144b", "Karma"},
            {"ae76cd591235ce2afe9ae3aab3f9e7", "Katy & Bob: Cake Cafe"},
            {"aea3f373af39a1a98949977fedf363", "Katy & Bob: Safari Cafe"},
            {"ad5b5db8d4c8d92892c547132e8879", "LandGrabbers"},
            {"b458ff3f97c238850702bf5f37935", "Lara Gates: The Lost Talisman"},
            {"11bd83ea97bf009ad8ac06824a752f", "League of Mermaids"},
            {"b3d8cd64af79a703f9029cec446f5", "Legends of Solitaire: Curse of the Dragons"},
            {"b361e736c241b9aa18707a5ca0c1d", "Lost in the City 2 Post Scriptum"},
            {"b3430540cf0ca236c89a4f893c263", "Malice: Two Sisters 1.5"},
            {"2c21b59f59d85cb6a316a354be7a7", "Masters of Mystery 2: Blood of Betrayal"},
            {"28f9599855486b190313d2cc646279", "Monkey's Tower"},
            {"6e7e171bcb2ec79d31f12c280ba3bd", "Mysteries of Horus"},
            {"b45c463600fe35995344851953677", "Mysteries of Magic Island"},
            {"7a5a35c7916d3872d95de677430d4f", "Ocean Express"},
            {"b40f8e7e744c346213e1e1ec6e155", "Off the Record: The Final Interview"},
            {"2040e1e19f029cd71828bd04072d7", "Pahelika: Revelations"},
            {"f4d4f5255280cbe19b236c1730ea9", "Princess of Tavern"},
            {"6e8ddc21a6a1f2656b1deff7cfe9eb", "Psycho Train"},
            {"b3a0234b39542e0f5a29b05d111d5", "Rhianna Ford & The Da Vinci Letter"},
            {"63d0ab99b5a14cec75951228eb0b21", "Robin's Island Adventure"},
            {"6e5725b013d11025c4335ef8a0327b", "Sea Bounty"},
            {"b3f411caa6603b150bbdbbf6a8fd3", "Serpent of Isis"},
            {"23e381983e7b5af65a1b6244ff96e3", "Streets of Moscow"},
            {"befbbb74cf91cf5e25e42f1aee5f9", "Tales of Empire: Rome"},
            {"b3088545404f9ebb30a5e7794a3a9", "The Count of Monte Cristo"},
            {"6e8b01fe7bae51febd75463ab95d29", "The Happy Hereafter"},
            {"a06ad0b5213779cc85f65be892a9f1", "The Surprising Adventures of Munchausen (English)"},
            {"205fdb97f80eccd9ef88eda0c709b", "The Surprising Adventures of Munchausen (German)"},
            {"2919c786838ef7b58a61cddda1b3af", "The Tarot's Misfortune"},
            {"f8d90e546ade087d615188becae4b", "The Voice from Heaven"},
            {"6e32ac1c31c7189e69ed837dd595ed", "Twisted Lands: Shadow Town"},
            {"6e4cb4a57910c6edf675960adfe3e3", "Twisted Lands: Shadow Town"},
            {"209eb50f88cca4ff7433033adaa515", "Twisted Lands 2: Insomniac (German)"},
            {"6e2dc24cf1c870dcc108944e605675", "Twisted Lands 2: Insomniac (English)"},
            {"6e27c1f253390d09287ad71a71d4b1", "Twisted Lands 2: Insomniac CE"},
            {"6e395dfc41de29b145f10d0d7800c7", "Twisted Lands 3: Origin"},
            {"b36c71dd093357f93096ea4ddedd3", "Unfinished Tales: Illicit Love"},
            {"b306272f5065132643b8586226ff5", "Unwell Mel"},
            {"6e5c029478a2b19267dbe48ed8e90d", "Vacation Mogul"},
            {"7e13dfb068aa29d77cee1f80f49821", "Vengeance: Lost Love"},
            {"adb553ddec488789795dd1ab8a12a1", "Vogue Tales"},
            {"4053cd51386e71795cdd8a23e4621", "Voyage to Fantasy"},
            {"c8e5a57c85467b6be4e70393b2e05", "When in Rome"},
            {"e852cadc609d29742b59f60957655", "Witchcraft: The Lotus Elixir"},
            {"b4540565d76bd9d9eedb11611bae5", "Yuletide Legends: The Brothers Claus"},
            {"29f0e7de58a1c571280997afcc9c53", "Zen Games"},
            {"7e6a8cc8ef9c049da0970956fc17e9", "Zombie Jewel"},
            {"1656af27c2d922dfe2f90a763cfe33", "Company of Heroes: Tales of Valor (DVD)\\validators\\gguo+drho+gtho+mtbo+toho+ddho+rspa"},
            {"962d841c45d03c6d49079559ecf77", "Company of Heroes: Tales of Valor (DVD)\\validators\\ddt"},
            {"24688dc284a7a5acea99591a504d85", "Company of Heroes: Tales of Valor (DVD)\\validators\\gtwc+mtbc+ggic+nxrc+topc+dnrc+drpc"},
            {"3823847ad9e211ab26d03a5ea50edb", "Company of Heroes: Tales of Valor (DVD)\\validators\\ggge+drge+gloc+dsge+nxge+toge+mtge+gtge"},
            {"382fe9b17356853bba1c0a315c297f", "Company of Heroes: Tales of Valor (DVD)\\validators\\ghoti+togt+nxgt+mtgt+gggt+dugt+drgt+gtgt"},
            {"2852c6b73d42edc620f4ad9b0a672f", "Company of Heroes: Tales of Valor (DVD)\\validators\\dxdt"},
            {"82e67867f07e839ff0cca72436b7ab", "Company of Heroes: Tales of Valor (DVD)\\validators\\nxro"},
            {"3f762c7203036985e718cbb64468bf", "Company of Heroes: Tales of Valor (DVD)\\validators\\rd"},
            {"41a694dfdad19620d384f2576fc737", "Company of Heroes: Tales of Valor (DVD)\\validators\\rs"},
            {"6292738d294c705e7cf4f8c03ad33d", "Final Fantasy VII (Store Edition)"},
            {"70d8c43d42c8703c972383f8dfd463", "Final Fantasy VIII (Store Edition)"},
            {"6a64ddb197c109aa346a3b319a655d", "Sam & Max|Sea.3/Ep.2: The Tomb of Sammun-Mak"},
            {"2085de7c9d5361e881eb5bbcaad61", "7 Gates: The Path to Zamolxes"},
            {"7e14cee9f3ebb5462f4e8cf5d1e20d", "7 Hills of Rome: Mahjong"},
            {"e3cc9bfffb1d6737504969c374ecf", "7 Roses: A Darkness Rises"},
            {"630dc9dfa38727d4593b7691c5dfa1", "7 Wonders: Treasures of Seven (GFW)"},
            {"599164e0fd8445d69bbdf2d5ea8a7", "11 Islands"},
            {"20f151814853f8d18d62246aa1efed", "20,000 Leagues Under the Sea: Captain Nemo"},
            {"ae18b8bbbb781413c87a9f4c4a176d", "1001 Jigsaw: Earth Chronicles 5"},
            {"ae9427c09903e27022c706082e9075", "1001 Jigsaw: Earth Chronicles 6"},
            {"ae771fee8cb7e3876480e311877edd", "1001 Jigsaw: Earth Chronicles 7"},
            {"2116d8da9519bdb9d9d2033e991535", "A Vampire Romance: Paris Stories (GFW)"},
            {"2e410911eb5dc6db407778165c2ed3", "A Vampyre Story (GFW)"},
            {"bbb4835ce6c34a0fd4d7b43c425bb", "Abyss: The Wraiths of Eden"},
            {"6e30703aa5343da42b7e6560a9c5a7", "Action Ball 2"},
            {"2a8267c39fed5e281d60fb464968d3", "Agatha Christie: Dead Man's Folly"},
            {"188a81208df25ddd02c7ece6fbe669", "Airport Mania: First Flight"},
            {"2110e5bf85fdd97cad816eb1ca4aa1", "Alchemy Mysteries: Prague Legends"},
            {"2b3dbb575b3cfdd21f5c7deb3703f5", "Alchemy Quest"},
            {"fb65a44440d17bc7a752f3b340b63", "Alice in Wonderland (Polish)"},
            {"6e2e7ac71f20b6b8860ee5d60c90d3", "Amelie's Cafe: Halloween"},
            {"6e768b24528833b2fc408525c65251", "Amelie's Cafe: Holiday Spirit"},
            {"b4164a0b5ac4c356647a3ea59fef7", "Amulet of Time: Shadow of La Rochelle"},
            {"b371767f4a9b84070ffe4a28f0f81", "Angelica Weaver: Catch Me When You Can"},
            {"202265b013a70213e9503f4a47623", "Annie's Millions"},
            {"a401eddd32bd83516b7602a5c3731", "Apothecarium: The Renaissance of Evil (Japan)"},
            {"696222943802254d7cc9ab308b63a3", "Arabella the Fairy"},
            {"b3b0542d8b7fa874b4104659c454f", "Asami's Sushi Shop"},
            {"b4561f6397b787095a54360f8dd93", "Azada: In Libro"},
            {"2b3e30cec00c13a3a2f1cf3e39378f", "Aztec Venture"},
            {"c80555e26ee7dc58ecbaa7f9d145d", "Baantje: De Moord in het Royal Amstel (Dutch)"},
            {"6150a37b55fc163ccaa82bf0ac4ff", "BlackSite: Area 51 (Polish)"},
            {"28d4c218602867f23425f477907517", "BlazBlue: Calamity Trigger (GFW)"},
            {"4404768264f3fe37dc1ac215c07e21", "Bully: Scholarship Edition (GFW)"},
            {"b3e79cc51989a744fea9e55532bb7", "Burger Bustle: Ellie's Organics"},
            {"dfe770a407a8ea2e9c19629cbefab", "Call of Duty: World at War (GFW)"},
            {"68b0294eddc2799dfa1df986e4450b", "Call of Duty 4: Modern Warfare (GFW)"},
            {"85e6ea0da84aed4410a7272bf151c7", "Championship Manager 2010 (GFW)"},
            {"b3fe2d4f53d52b8cfc0346d172f87", "Christmas Stories: A Christmas Carol (French)"},
            {"b3a93545dd0029fbc6a6d411a5907", "Christmas Stories: Nutcracker"},
            {"b2f38f532cc746d37ba3110a75945", "Christmas Stories: Puss in Boots"},
            {"b315cb1d72271ab9354d4cd39d1dd", "Christmas Stories: The Gift of the Magi"},
            {"71303bfa5e60ab2209d6418a60a34d", "Christmas Wonderland"},
            {"710405929492d0b9f915acc28a58f9", "Christmas Wonderland 2"},
            {"db4f549530b538e8484171e5d299d", "Conflict: Denied Ops (GFW)"},
            {"ae905a2e5a56c9133e7c492d8964f3", "Cooking Trip"},
            {"199fe5a0b1a2449ed3f635f9c8a039", "Country Tales"},
            {"599312152887bb2d316c72ebf5855", "Creative Trio"},
            {"8deaf49740dad5fbf946bf074d5605", "Cubis Creature: Addictive Puzzler"},
            {"b3b1c25ddabf828841c5844107569", "Cursed Cases: Murder at the Maybard Estate"},
            {"dd190983547e986527710968e85319", "Cursed Fates: The Headless Horseman"},
            {"b4003d105ba8345bf14032f32b741", "Cursed House 2"},
            {"b4741a17ea32704c1a1bb698edd53", "Cursery: The Crooked Man and the Crooked Cat(French)"},
            {"b2ee262f07d7a908cba1e9ba11909", "Dark Canvas: A Brush With Death"},
            {"b470305749679fc2bc042cb97bfb3", "Dark Dimensions: Blade Master"},
            {"b36bbbfdca2613f57de54c5b53cf7", "Dark Dimensions: City of Fog"},
            {"b34eab5416505c58b05fee6b8c26d", "Dark Dimensions: Vengeful Beauty"},
            {"b489841bba7e14d84e9627505df8b", "Dark Dimensions: Wax Beauty"},
            {"b39dcbea23c98a123849ba3b6ba83", "Dark Heritage: Guardians of Hope"},
            {"b3b9e90d2d077742f05a8e0ff2813", "Dawn of Hope: Daughter of Thunder"},
            {"b481e100889f47d53d6aa925d5ee5", "Dawn of Hope: Skyline Adventure"},
            {"b2ff3c4be43fe3caf38343632bb19", "Death Under Tuscan Skies: A Dana Knightstone Novel"},
            {"1babd52744f03fdd4ad2d89b3d1705", "Defender of the Crown: Heroes Live Forever"},
            {"4fbd5af4c57fcc899a4e1aed04177", "Defender of the Crown: Heroes Live Forever (refresh)"},
            {"b3486f85b84096f6325dd661c4861", "Defenders of Law: The Rosendale File"},
            {"b4711fea5ac91ea942dc1bdbfd9fb", "Detective Quest: The Crystal Slipper"},
            {"aed12cebf8bd4fbfd2c20f5566b9fb", "Detective Riddles. Sherlock's Heritage"},
            {"ae9f5e14d03d0d5959a63dc9c76925", "Detective Riddles. Sherlock's Heritage 2"},
            {"aea40d1d76c6702e3005acf0898671", "Detective Solitaire: Inspector Magic"},
            {"133a76b06a38a8932689112dc71487", "Deus Ex (GFW)"},
            {"b6d4aecc9907100246ced9ef605553", "Deus Ex: Invisible War (GFW)"},
            {"529a4afd50d7f2558ed12b099ed973", "Disney/Pixar Cars 2 (Germany, France, Italy)"},
            {"1d8bbb11aaa15a67d403e5ae767ded", "Disney/Pixar Cars 2 (Polish, Chezh)"},
            {"48db08d8ed0899eda37a04334d0831", "Divinity II: The Dragon Knight Saga (French)"},
            {"de675814e83b19586e01828557221", "Divinity II: The Dragon Knight Saga (Polish)"},
            {"b381459451729e2930fb8d9fce59d", "Dracula: Love Kills"},
            {"6e8a18bf6c4e50a91af31f448e675d", "Dragon Crossroads"},
            {"b2f5e336285925d2f3e9729c42587", "Dragon Keeper 2"},
            {"1523b86399fd06f98bbb60901471d5", "Dream Builder: Amusement Park"},
            {"e2dedad4f2c255efe4a27b78a3da7", "Eastville Chronicles: The Drama Queen Murder"},
            {"b317ecb04c528c961e3e378552aaf", "Edge of Reality: Lethal Predictions"},
            {"b42394329ffd64b80a15652a1c82f", "Edge of Reality: Ring of Destiny"},
            {"ae14e4b06ca7680218c0188e66071f", "Egypt Picross: Pharaoh's Riddles"},
            {"aeae153c4971666d3aebdbc3afbfeb", "Egypt Solitaire: Match 2 Cards"},
            {"28e5f69f5854f559d6fb527592754f", "eJay Techno 5"},
            {"6e69bc8f341c8ea9e987c562595569", "Enchanted Cavern"},
            {"6e282253a9fd421cae30921a2844f1", "Enchanted Cavern 2"},
            {"b2fe7f0d4531330b4b83765a49d51", "Enchanted Kingdom: A Dark Seed"},
            {"b392aec48c4c1981b9ce757206e9d", "Enchanted Kingdom: A Stranger's Venom"},
            {"b43926078d8273aac606ee427a4fb", "Enchantia: Wrath of the Phoenix Queen"},
            {"b3919e972099e52ae0741d0ffb3f5", "Endless Fables: The Minotaur's Curse"},
            {"b3541d0917a60f562ef993cb9b8bb", "Endless Fables 2: Frozen Path"},
            {"e1b957d96190e7d7e4b414069304d", "Eternal Night: Realm of Souls"},
            {"f8a9a90d3f93d11c556a759d4e1e9", "Eternity"},
            {"6e432608db33cc17d1ed0fb83986d7", "Evoly"},
            {"196901195f7f3c5b164c6e0ace8ce1", "Exorcist II"},
            {"2b6155ce50711f28733c4b7e4af3f3", "3D Mahjong Deluxe"},
            {"aeebe153c80fbad64ff31fa702de37", "F.E.A.R. 2: Project Origin (GFW)"},
            {"4ed99a2c286c4dd01ce0498bcc69c3", "Fable: The Lost Chapters (GFW)"},
            {"31e2f9359f44fed9c1ad7c70934e05", "Fables of the Kingdom"},
            {"b35939fdd5cd976bbcc5b753882dd", "Fairway"},
            {"b336cc75ddc62ba0523e24af26e03", "Fairy Maids"},
            {"ae4dcd4425e6d440f64d50f3dc9f4f", "Fairytale Solitaire: Red Riding Hood"},
            {"202b402fb96ee50cf538d42b275f5", "Fall of the New Age"},
            {"2514cd0d5cf679ec8117d120ae11ad", "Fallout 3 (GFW)"},
            {"3b92c03425c7a1f0c830bd4e418233", "Fallout 3 (GFW) alt"},
            {"e0d0cd2b5cda4a152d4ff49c5ae65", "Family Vacation: California"},
            {"1131285bd49baf041852ce2083932f", "Fantastic Farm"},
            {"ad93cbda5bc92ba77fee50746e08d7", "Farm Craft"},
            {"1a1db0f936042d5e9b8fb7b35b31f7", "Fashion Forward"},
            {"b46473f479ea77a3552dc926b9cef", "Fear for Sale: City of the Past"},
            {"b392b620e1d209ed939df78ae9965", "Fear For Sale: Hidden in the Darkness"},
            {"b497bf03e03ca6d40560f067de63b", "Fear for Sale: Mystery of McInroy Manor"},
            {"b452100db7b6baa09ed2b17e5dd43", "Fear For Sale: Phantom Tide (French)"},
            {"b4117db726991d25107c524022321", "Fear for Sale: Sunnyvale Story"},
            {"b2ec2e3cf2d7d704f68f8ead923e5", "Fear for Sale: The 13 Keys"},
            {"b3fa89eb8bdd84e6854dbda32eef1", "Fear For Sale: The Curse of Whitefall"},
            {"b2ff91d269257422a8b1dc6bf97cd", "Fear for Sale: The Dusk Wanderer"},
            {"b325aeaabdd499f98358c3e55e913", "Fear for Sale: The House on Black River"},
            {"1537a66a17b178b44235e2cba21b3f", "Film Fatale: Lights, Camera, Madness!"},
            {"b38b90364d6e6a0c006ee027f86f5", "Final Cut: Death on the Silver Screen"},
            {"b41d67a39b6a3f1961d7641a6a8d7", "Final Cut: Fade to Black"},
            {"b3ca6f13bfb7b79d4ba2d45e4f1ad", "Fisher's Family Farm"},
            {"24483f6ef9bb228ef2de8789c041b7", "FlatOut: Ultimate Carnage (GFW)"},
            {"6e7b651d9b62259e162cbbcaea2851", "Flower Quest"},
            {"b32a23f6b9b56cd79431e3ab06f8d", "Flux Family Secrets: The Book of Oracles"},
            {"b463f7e1fa2e6e80bc821dde31319", "Flux Family Secrets: The Ripple Effect"},
            {"59b42d7d571477b5f9d1555d077b07", "Fruit Lockers Reborn!"},
            {"3006c3d26022bce37b58b95b57ef87", "G-Force (Polish, Chezh, Hungary)"},
            {"2b5ca51585e209da3b5ace3f7ff40d", "Galaxy Quest"},
            {"2121111d0b5e2893b264f1851e02a1", "Garden Shop"},
            {"4191f55a872cbe11ab2f204d621d53", "Gears of War (GFW)"},
            {"6e62b05b0b78d897444d3bc3006a87", "Sacra Terra: Kiss of Death"},
            {"6b64816abdde8a30e4e0c4e500601d", "Ghost Encounters: Deadwood"},
            {"81ca4bc38eb9ec8d1e8541246de9c1", "Ghost Town Mysteries: Bodie"},
            {"ae3943dd083d67997db963e2d1a235", "Gnomes Garden: Christmas Story"},
            {"ae3266aa61af0eaa30e6ce668c31db", "Gnomes Garden: Lost King"},
            {"ae3cc0b28d730f65aebb775823c903", "Gnomes Garden 2"},
            {"aeaa5c2e6f47d876a50437c6d35c3d", "Gnomes Garden 3: The thief of castles"},
            {"b366d3d877ca742efca62de7b262d", "Grave Mania: Pandemic Pandemonium"},
            {"b3f3eabcbd77f3db9b3dbd6622cf7", "Grave Mania: Undead Fever"},
            {"b3fcd342fb269dd0cffaceae4267d", "Gravely Silent: House of Deadlock"},
            {"ba8074cf4665dd75cb0bbcb554603", "Green City"},
            {"b429ec1bd02be88d1915a3cf3f3c5", "Grim Legends: The Forsaken Bride (French)+Death at Cape Porto: A Dana Knightstone Novel"}, // error?
            {"6e755a6872a1b7253d6ee229f62397", "Happy Chef"},
            {"2a510558840b24122cf0be6be10999", "Happy Chef 2"},
            {"49db4d702986d76a7adc0959ab1933", "Hitman: Blood Money (GFW)"},
            {"6e7aeba598e98f90481bb7758d4adb", "House of 1000 Doors: Serpent Flame"},
            {"b3bbf7532455f132c6eaa061954c7", "Howlville: The Dark Past"},
            {"ea7c96dd997867ebde67d5f82e33f1", "Hunted: The Demon's Forge (GFW)"},
            {"adfd69f24daf3a9b0a8a09d7380acf", "Ice Cream Mania"},
            {"2a4ae406270daf5b3eb9beab95e62f", "Incredible Zoo"},
            {"6e7a46dc250a4e87b103186ccb4551", "Island Realms"},
            {"d30b40e221d6f162b7216bb05e7c1", "Island Tribe 5"},
            {"c00eac1b7f3ccf67445ddddc1c61d", "Jewel Link: Legends of Atlantis"},
            {"375dae291d5cd66769043ea8a90cab", "Jewel Legends: Magical Kingdoms"},
            {"f3c9d7715a45b4f54de6d8c5380bd", "Jewel Legends: Tree of Life"},
            {"7e325c8fa4de5e9a8807a0c4421305", "Jewel Venture"},
            {"6e41e94751aa86667df8d344a86439", "Jigsaw World"},
            {"1db409be9835bbb6345e6b4fdf7f93", "Josefine Skolehjelp: Jorden har feber (Norway)"},
            {"b40a08caefd9a792b1f422f51ec37", "Maze: Nightmare Realm"},
            {"2b3db1ce9b396a774eed7d4a4a4b23", "Paris Mahjong"},
            {"6e80bec907e669e2649565fa169e29", "Journey of Hope"},
            {"f74f71d0dc771842aebae021820ef", "Jump Birdy Jump"},
            {"6e1f157b6c49a3457252a07a83a2ff", "Jumpin' Jack"},
            {"dbe185db5d5fa6f1b741489b1c8f5", "Just Cause (Polish)"},
            {"cb788885a0d665d48ab9c566f02ab", "Kane & Lynch: Dead Men (GFW)"},
            {"8593b78d620b0681b371d8adabaac7", "King's Bounty: The Legend (EFGS)+(Italian)"}, // error?
            {"ae316ccf1e4ee37572fb5deeebcc57", "Knight Solitaire 2"},
            {"ae1d2b624628944cd9d604bf45c95f", "Knight Solitaire 3"},
            {"2a4db678103699fc64232a2dc98655", "Kona's Crate (GFW)"},
            {"adabaadd415d9d4556d0bc7f9a8ef3", "Laura Jones and the Gates of Good and Evil"},
            {"ae13ece205bdb8f503f28672511d37", "Laura Jones and the Secret Legacy of Nikola Tesla"},
            {"b45fb5194059c95cdb1c7ed8d30c9", "League of Light: Edge of Justice"},
            {"b34c10e9e4523b6f7eec1596ee917", "League of Light: Silent Mountain"},
            {"b413974973e1755dc8b3de16c1487", "League of Light: The Gatherer and Silent Mountain"},
            {"1a1b164702f264ff0cb32bf3362f53", "Legacy Tales: Mercy of the Gallows Walkthrough"},
            {"d660735a60e004999bb8f55be16611", "BioShock (GFW)"},
            {"4937b160a6bc574583def073766ae1", "LEGO Batman: The Videogame (GFW)"},
            {"f7e3d6fb2906b37389aab5a36dc47", "LEGO Harry Potter: Years 1-4 (GFW)"},
            {"16bdeb770fef53b04fc0ce0dbdf849", "Little Farm"},
            {"1a0e694aebb0df5a3ea4445f7e18c5", "Little Mermaid Bubble Shooter"},
            {"58bde348c78d844ffd599262ec8bb9", "Lost Planet: Extreme - Condition Colonies Edition (GFW)"},
            {"157760e3b10a89117e9f9cddee2233", "Lost Planet 2 (GFW)"},
            {"8a63c5a04880c0de60c9008db8b33b", "Love & Death: Bitten"},
            {"b44c9754173d9ee6cf5685cc3b515", "Macabre Mysteries: Curse of the Nightingale"},
            {"b37076c7b7f6834734be052599849", "Maestro: Music from the Void"},
            {"b40c983c53139ea8af5b45d320337", "Maestro: Music of Death"},
            {"b3784b60185f5479f883e171fafad", "Maestro: Notes of Life"},
            {"923e2251347040175ec8827e90a83", "Magic Life"},
            {"ae1a2761d97d47128fbde5dadf49cd", "Mahjong Magic Journey 3"},
            {"ae79c1f831d0dec79e2b8fd63bf32b", "Mahjong Valentine's Day"},
            {"6e41d3cb656ef87bf34546bebe6f85", "Mahjong: Wolf's Stories"},
            {"de43ce36b350c55d98cb812564005", "MatchVentures"},
            {"b46c22270b1860a765cb0396cb129", "Maze: Subject 360"},
            {"112b57e257cd70be045c1de7bb108d", "Megapolis"},
            {"6e3d45f86c40e9b6c703b9889e3cc3", "Meridian: Age of Invention"},
            {"b2fb11b5b6a4cb0df1df40c1799ad", "Midnight Calling: Valeria"},
            {"adf080e7912f36462c445b97bb8f39", "Million Dollar Quest"},
            {"94a58eefa49245f05ac53d2ac7aea3", "Mini Ninjas (GFW)"},
            {"6e3c1932e9fa085d199b7bb94c0319", "Moai VI: Unexpected Guests"},
            {"3dc1033dfff9ac46b4e95d825cb1af", "Mountain Crime: Requital"},
            {"1968d1eb3726baffd6e337d0e1ef7f", "Murder on the Titanic"},
            {"6e6c4a2233c70df36e863ea4c9be5b", "Mystery Cruise"},
            {"1997eec553a9735ee8d72be218f6f5", "Mystery P.I.: The New York Fortune"},
            {"ae047240d62bd3ae7ffa40e10068fd", "Mysteryville"},
            {"b319f360bd21ee5aeb5e15db276dd", "Mystic Inn"},
            {"72fbbe4ddfdb35ee7ee4098022c199", "Mystika: Between Light and Shadow"},
            {"114500e2f446c1b92494e1ae1b97b1", "Nanny Mania 2: Nanny Goes to Hollywood"},
            {"b41514b0dedf17d14a34dd82b86ed", "Nemo's Secret: The Nautilus"},
            {"b30e4ddc568ec00184db8e13a4ce5", "Nemo's Secret: Vulcania"},
            {"85cf716ab993de13e2f47ee373a309", "Neverland"},
            {"b310d48d73aa0526138cf214f6513", "Nevertales: Forgotten Pages"},
            {"6e2801493d7180338b2df8e7da964f", "New Yankee in King Arthur's Court 2"},
            {"6e5490d70de520900d43da1193b4a1", "New Yankee in King Arthur's Court 4"},
            {"6e5c3bed36c2a481a786b545fb4b33", "New Yankee in King Arthur's Court 5"},
            {"6e39defc22c846001b972504dd238d", "New Yankee in Pharaoh's Court 6"},
            {"6e1ef5bc553377c34ed96c7d950a4f", "Sky Kingdoms"},
            {"1e45a950952bd9accf92fc0e4442d1", "Nikopol: Secrets of the Immortals (French, Spanish, Italian)"},
            {"f42e374a3e78b9cb9bcfbf5683f37", "Star Defender 4"},
            {"6e7663b83ce3b16372288dc4ed34cd", "Terraformers"},
            {"b3f1e9d41e9430ac795b282b34239", "Ominous Objects: Lumina Camera"},
            {"b2f8676eb851e1f199a5d2e2be177", "Ominous Objects: The Cursed Guards"},
            {"b435e1d43f65e6f7115be3d25bcc5", "Ominous Objects: Trail of Time"},
            {"576061363bdc4dbeaf5734111a9375", "Our Worst Fears: Stained Skin"},
            {"6e74cdbe317d0a1fa9fe9e82da6925", "Outta This Kingdom"},
            {"20e8d63d3a6eceda155ff304ec399f", "Overclocked (German)"},
            {"596ecaf1ea8002c4e994a10ce6131", "Pakoombo"},
            {"6e17c682d82abeaeb8cf1d882c2837", "Path to Success"},
            {"b2fa676801e072d99630ee0584cdd", "Pathfinders: Lost at Sea"},
            {"e3337c9b47b515efc74f0db63e833", "Patrician IV: Conquest by Trade (GFW)"},
            {"ae2ef8daee6f2f83279400fae6562d", "Penguin Rescue"},
            {"b3191c6be6c2b4c3a14de04adddd3", "Phenomenon: City of Cyan"},
            {"6684a2547c3fd93e4a2e0596b7657b", "Plants vs. Zombies (GFW)"},
            {"64526288a7f778e919d9df1c09f2cf", "PMDG 747-400X"},
            {"4fd72ffea76c573ff73c48547875a9", "PMDG MD-11 FS9"},
            {"3c8376f39b03b3c3f5dd057ca45bcb", "PMDG MD-11"},
            {"ae672f1bb3d95074e47e603722d379", "Portal of Evil: Stolen Runes"},
            {"74bf57e6d61e90e607b19b6a7f4169", "Power Rangers: Super Legends - 15th Anniversary"},
            {"6e2c87a02b8b3d4c684e21dc81bfc3", "Prehistoric Tales"},
            {"3468a7d6b53419efa3e591684d9989", "Project: Snowblind (GFW)"},
            {"b322c2c8ed3ad4029dde64cdc6dfd", "Punished Talents: Stolen Awards"},
            {"c489f89505ed2a359b6f6de8e817ad", "Puppy Stylin'"},
            {"e8388b170a09d3230d9900bebcfe1", "Queen's Garden"},
            {"203ade6375697ffbde4c6382480b1", "Questerium: Sinister Trinity"},
            {"80ae39f62d955cafd455b2c5dd59a5", "Red Crow Mysteries: Legion"},
            {"b31d9bbb13361d38ba8f488ae2199", "Redrum"},
            {"b4414131879c3b24cec1df7bc54d7", "Redrum: Time Lies"},
            {"b478c296bd91d562435e97260e97d", "Relics of Fate: A Penny Macey Mystery"},
            {"6e8fcb5666e42261d6115f03afb343", "RoboBall"},
            {"1a3be7ec2fd756f7bd904a47ba9c5", "Rome: Total War (GFW)"},
            {"1d3b8b7cc609b36883aebb1dc1240f", "Saints Row 2 (GFW)"},
            {"c066bdda2e326036af652f6c54c207", "Save the Furries"},
            {"1b2bdc5d9bcb27240706593205dab9", "School Bus Fun"},
            {"b4746101befd1513f3dfc32708eb3", "Shaban"},
            {"2114221d31469cce71e78e51cab9c5", "Shadomania"},
            {"47a6a1c0a1eb643990b51d21ab689", "ShellShock 2: Blood Trails (Polish)"},
            {"6678c47867c8e27a19a42c3a353493", "ShellShock 2: Blood Trails (Russian)"},
            {"b3732dd5ddbca467ab87894b06955", "Time Relics: Gears of Light"},
            {"f5f8370c29dcee77befb140ee2601", "ShellShock 2: Blood Trails (American)"},
            {"b2f946288712e821c63eac5febf63", "TV Farm"},
            {"199e2ca068233cf437b389bc31fe2f", "Where Angels Cry"},
            {"b39431ea71dc826cf2ca29a53b3cd", "Wonder World"},
            {"a5a7ea28cb82573d7a7143546afa7d", "Riddles of Egypt"},
            {"1d1a5c8cccc55f5f41d7aff8b3d10f", "Silke: Pixeline Lillesoster - Syng, Leg og Laer"},
            {"3b4f34b07b0956bf6d86a35b806b75", "Split Second: Velocity (Polish)"},
            {"1a126f669fdc4c28242b0b23e3cf1f", "Star Wars: Knights of the Old Republic II - The Sith Lords"},
            {"abf02e00c7619182672fdec8390037", "Sunrise: The Game"},
            {"155b59f7507fb80a31eda6ba415b95", "Supreme Commander (Polish)"},
            {"cfa732124c5da0e046461495f63537", "Test Drive: Ferrari Racing Legends"},
            {"303f82a4fd5588eac455e8bc7a2b1d", "The Chronicles of Narnia: Prince Caspian"},
            {"1ec74d1ff238b07fe1cc1f8d3bd779", "The Club (GFW)"},
            {"4294d6d3102cfb183671964d403733", "The Next Big Thing (French)"},
            {"8cf0a049f44c5eeff7c4f69385ceb", "The Next Big Thing (German)"},
            {"19a8befd50b604b2680ceac7c168d7", "The Secret of Hildegards"},
            {"4dd5a72bb26336dcd58462e11e91af", "The Sims: Medieval (GFW)"},
            {"266e032e3d868872df8496ac025407", "The Void (German)"},
            {"1b0926af0b0be8909c17adb7394661", "Thief: Deadly Shadows (GFW)"},
            {"5279fd013cac9077e7bdf0793cea09", "Tomb Raider: Underworld (Polish, Chezh, Hungary)"},
            {"9a6ffa5c0d1651361b1d22dc8bb07", "Disney/Pixar Toy Story 3 (Polish, Chezh)+Tropico 3: Gold Edition (GFW)"}, // error?
            {"33c98737fa6395f3b994d2145e29d3", "Universe at War: Earth Assault (GFW)"},
            {"6e3f380f34f3ef32d85c7ed5ca5f1d", "Vampires vs. Zombies"},
            {"309bf497a575c331a884e66330bd6d", "Venetica (Italy)+(German)"}, // error?
            {"3459a9b686d2eabcd9d5f647f03351", "Viva Pinata (GFW)"},
            {"689b23269e507e5648f5dd705befaf", "Wedding Salon"},
            {"1424daf5c678fe4d81a92e42a15b11", "Brain Tonic: Force 1"},
            {"1a581fe1903209b2076c21f10b67cd", "Youda Fisherman"},
            {"b94ad6f19103e0e216cdc916265cf", "Zoo Tycoon 2 (GFW)"},
            {"8a9f177e36251610d1b2977c924225", "Zuma's Revenge! (GFW)"},
            {"4409914233235e774161634944aa3f", "Dasha Vasiliewa: catwooman delo (RUSSIA)"},
            {"bdffb7402703518d8f5bff7890b95f", "Evgeniy Onegin (RUSSIA)"},
            {"b30a4603b7ce8bf34523ceaddec21", "1 Moment Of Time: Silentville"},
            {"8e358c4d51f6b1acde6bc03e1a8ae3", "Johanna - Matemaatikaralli (Estonian)"},
            {"b47178c60ee58a69e2c4a86fbcf61", "Artifact Quest"},
            {"21e5e8cb29fb4fd70e18539e99fa01", "Atlantic Journey: The Lost Brother"},
            {"b330fd8dd2c2ccff6d8d92e9a79ef", "Be Rich!"},
            {"b408b581bcb1b4b0694e7fffbc3d3", "Be Richer!"},
            {"b360d4eff1461826a28c563d3d4fb", "Blood and Ruby"},
            {"59152fd4fcff0dee1adecf6248b0a1", "Bloom"},
            {"1571bb92387178e0215eb7b4f5fdcb", "Burger Bustle"},
            {"b395d512c361b936f6f91338c9f85", "Campgrounds"},
            {"b3aa8cfc1f1924a5d5975f2a15eeb", "Chef Solitaire: USA"},
            {"5920438b88650ec2854c63324d45ff", "Crime Stories: Days of Vengeance"},
            {"e12e95abd84475d2d33f911403451", "DragonScales 2: Beneath a Bloodstained Moon"},
            {"ada4b8cdcecee2cfb8b4edd065119b", "Dream Sleuth"},
            {"2a88ef650b34adaeabe130d7c4460b", "Dream Vacation Solitaire"},
            {"6e4bab2c9fc06f06c1b70b02121459", "Fashion Craze"},
            {"207a204331623d72513313a2a96b7", "Fishdom H2O: Hidden Odyssey"},
            {"2ad0da1dd4838120d3f9684178fb7d", "Galapago"},
            {"6e88a7023752007ea3aca429c73c8b", "Haunted Domains"},
            {"6e224c57868cf42d88fb08bc0be221", "Jewels of the East India Company"},
            {"ae1f7125293d42df988904d2edb2d7", "Katy & Bob: Cake Cafe (Collector's Edition)"},
            {"11205ce6ba63f6e6cce9afc2174aab", "King's Smith II"},
            {"f80776e2c09e0781bcfa15df11dd9", "Lost Civilization"},
            {"b30146c77280ecf23129009026f79", "Lost Secrets: November 1963"},
            {"91b9af5bcec2d176cffc29bf4c9aef", "Margrave Mysteries: The Curse of the Severed Heart"},
            {"b3f629bea44cf6be817e76a5f0c1f", "Maze: The Broken Tower"},
            {"b491ee98feea4b29ed0cd58203db5", "Midnight Calling: Jeronimo"},
            {"b39522a0455405c8e0ee51700f027", "Midnight Calling: Wise Dragon"},
            {"6e1520a5f337203fcd9ee13f6d1073", "Mind's Eye: Secrets of the Forgotten"},
            {"b3bc424ec1dd2f154b50caf0dcca9", "Mystic Diary: Haunted Island"},
            {"b38b5610f7055446610093b5a9441", "Mystic Diary: Lost Brother"},
            {"b3bb2a2fda87dba5005aaa3ccb15b", "Mystic Gateways: The Celestial Quest"},
            {"b38d58788a1356b58d3ddfda68039", "Mystic Legacy: The Great Ring"},
            {"b3ed04ac5352f3d992ca0caa59b3b", "Nevertales: Hidden Doorway"},
            {"b3cdbb3bd61f1cc069a25175e9cd1", "Nightmare Realm"},
            {"c9af0d09c2ff23ad639466e02f60f", "Northern Tale 3"},
            {"cc6c61eca72fdb80a064cd5d630a1", "Northern Tale 4"},
            {"6e6871ef976ce2ce058a31f70ea20b", "Panopticon: Path of Reflections"},
            {"2102e9697db1ca44640c19bb5980f", "Potion Bar"},
            {"fbc162fc9e3492b4d837ab0f87641", "Puzzle Express"},
            {"6e2c00f134c4245d6a32be6833d791", "Rune Lord"},
            {"46e0f27c3f16ff1eda5ec7889f005f", "Sacred Almanac: Traces of Greed"},
            {"1d5f27ca5ad82557c74aca2285441d", "Saving Private Sheep"},
            {"6e598759170869fe27d6a4487881bb", "Settlement: Colossus"},
            {"b3d34e9d4521648e763dba92a8b55", "Shades of Death: Royal Blood"},
            {"6e17a2702ad26d89b6c8e6e8d84ddd", "Sheep's Quest"},
            {"4a259812c0dbff4822ea5eb38a965", "Sinister City"},
            {"6e17e5669de741e7e013ee00fd0271", "Traffic Jam Extreme"},
            {"6e655c71b31404fa45f3dbb09cb439", "Treasure Mole: Winter Vacation"},
            {"6e65c2033c72cd06a15a7a5b54956b", "Viking Brothers"},
            {"6e0dfd56c21e58f730f867388732ab", "Viking Brothers 2"},
            {"6e6f94b60382c84ce01f513a2e9413", "Viking Brothers 3"},
            {"6e534d9f5b3f4b598d2e14b38043d1", "Viking Brothers 4"},
            {"6e1ccb88b7fcd957a57d25ff80c797", "Viking Brothers 5"},
            {"d06fb3de9bfa855a75ad18b0f101d", "Viking Saga: The Cursed Ring"},
            {"466fe64c951b0abad856f8d3e5a983", "American Girl Kit: A Tree House of My Own"},
            {"ae37488dd78c5b2a38fa57789976eb", "1001 Jigsaw. (World Tour) Home Sweet Home"},
            {"aed3ae5bb2fe6b918d1c043e969c4d", "1001 Jigsaw. Home Sweet Home - Wedding Ceremony"},
            {"ae480fc0038b91fe9dcda703d3b29d", "1001 Jigsaw. World Tour - Africa"},
            {"ae5f8f8512b91a423c1d432c4b2d59", "1001 Jigsaw. World Tour - American Puzzle"},
            {"ae7f545d2b65cf65917144aa70c59f", "1001 Jigsaw. World Tour - Asia"},
            {"ae8621feb692981f39b9f046ccba65", "1001 Jigsaw. World Tour - Castles and Palaces"},
            {"ae47215db07f166cec5b1d114cdd99", "1001 Jigsaw. World Tour - Great America"},
            {"6e66b73452642104bc7fe92a1c2dbb", "1001 Nights: The Adventures of Sindbad"},
            {"4adf95825ac9a21232d15ed68efff", "12 Labours of Hercules+12 Labours of Hercules VI: Race for Olympus"}, // error?
            {"4ad83fdbf025d379ef8453b8c8ac1", "12 Labours of Hercules II: The Cretan Bull"},
            {"4a899c643ffe1b6c4a2e4867c4941", "12 Labours of Hercules III: Girl Power"},
            {"31878a1a2cf1cc2fd5a59960d4cb7", "A Vampyre Story (Japan)"},
            {"c96a761339cfc26dc4b87899aebff", "Adelantado Trilogy: Book Three"},
            {"cb835cdf154ac43521937e13a15d1", "Adelantado Trilogy: Book Two"},
            {"6e1b458577f36c657e2b4512f70e2f", "Alexandra Fortune: Mystery of the Lunar Archipelago"},
            {"ae671e43c32f3f722f356629d7429d", "Alice's Jigsaw Time Travel"},
            {"ae6fc349de6bb276ce6948cdeb6d5d", "Alice's Jigsaw. Wonderland Chronicles"},
            {"ae1ec75a72f23c4814269e491a1433", "Alice's Jigsaw. Wonderland Chronicles 2"},
            {"6e752f7c5e5a183205ff31714417c5", "Amelie's Cafe"},
            {"6e51ca23b9f24a8ea1ad7a3731d47b", "Amelie's Cafe: Summer Time"},
            {"2a7e2dfc35b99e9be0ba370bdc9e6d", "Anno 1701"},
            {"b3c9a0b7873c669acaaa06e9ac43f", "Antique Road Trip: USA"},
            {"6e118d4f265351baeb78537720067b", "AquaBall"},
            {"2060530b0bc1a19502d18cebbb76f", "Aquascapes"},
            {"6e8189920cac2fd01fd74f2b6f67db", "Arctic Quest"},
            {"6e5e72d2365888df19dbc2b8ac52ef", "Arctic Quest 2"},
            {"42ea106e8c5aaa01c0ef4188a34da3", "Arma II - Reinforcements (USA)"},
            {"bea5dfda20ebe323c3d9ce2705e47", "Art Mahjongg Egypt"},
            {"2b63e2d4c01864fce38fc055bca65d", "Atlantic Quest 2: The New Adventures"},
            {"7e704fddc4df085b8644ad7d66c78b", "Atlantic Quest 3"},
            {"b42999ea16cad977103a7c96426d5", "Atlantis"},
            {"11b354f930ba87b4bf7e34dc994c47", "Atlantis: Pearls of the Deep"},
            {"2b27f229fc17d14a80bcd221e1eed", "Avencast: Rise of the Mage"},
            {"b33b608b04f0a1324cd35dd5a4b85", "Awakening: The Dreamless Castle"},
            {"b39c7ab21aad0a419d22651b53d63", "Awakening 2: Moonfell Wood"},
            {"b451bfa7c1a5e70b900169d8a094f", "Awakening 3: The Goblin Kingdom"},
            {"2015de185559a6d2d1120a6078955", "Barn Yarn"},
            {"6b8d2731351a6f6b9816e09180cda7", "Battlestations: Midway"},
            {"6e0def831dae4c533be3144f541b01", "Beach Party Craze"},
            {"6e4b09b9df389b449162a5ff831429", "Behind the Reflection"},
            {"20dc3c78e55b0b2b2bd11886bab253", "Beyond The Invisible: Evening"},
            {"5bb0537d7f23f3a109857899d49a6f", "Biohazard 4 (CN Traditional)"},
            {"afdd011ee49a44de2b6c8d31d0637", "Biohazard 4 (Japan)"},
            {"360e264e734389bf0495309858e449", "Bookstories+BookStories: In Search of Words"}, // error?
            {"21e0b36c538d3cc2aef9581774807f", "Borderlands (D2D)"},
            {"a38abf2b4f6433cebeb2ff8fdf4cb", "Borderlands (Metaboli)"},
            {"6e4a8d360f22a30782fcdcefa3a5a1", "Braveland"},
            {"2a8fec954b3e6f04d7ac867dcb2ecf", "Bubble Town"},
            {"7a864104330b1662590849bd5a24b9", "Build-A-Lot"},
            {"7a8fdaf653deef470278c18b498333", "Build-A-Lot 2: Town of the Year"},
            {"7ab753f32166fa7d94162b2bfa7bbf", "Build-A-Lot 3: Passport to Europe"},
            {"7a912211e382e2075b8cd12bc52d4b", "Build-A-Lot 4: Power Source"},
            {"af1084e208d03214cd8083450c4c3", "Bully: Scholarship Edition (D2D)"},
            {"203c0071d0a36c08d1d0c2e1f1723", "Call of Atlantis: Treasures of Poseidon"},
            {"5ede70f919c15f77d7c81fcd12175d", "Call of Duty 4: Modern Warfare (D2D)"},
            {"44942d35e310688e269223334afa9f", "Castle: Never Judge a Book by its Cover"},
            {"b469b7c8da206b749201521a90baf", "Cave Quest"},
            {"48b8358edef1f558d62efd7f35395f", "Chicken Invaders 2"},
            {"6e57d773e0cb476fb8c87cf4d6c9a5", "Claws & Feathers 2"},
            {"6e7cfff126188bdf69057ae736e12b", "Claws & Feathers 3"},
            {"c0448fa89554f1c48e249d46424ac1", "Clutter"},
            {"f4fdba8ffc611f78fe9f740661887", "Coffee Rush 2"},
            {"6b5fa7556630415d7826e67b995349", "Coffee Rush 3"},
            {"e3efdb07623fa07901697603915f5", "Crime Solitaire"}, // why is this here twice
            {"e594414a97fbd97c04cb40553cd5f", "Crime Solitaire 2: The Smoking Gun"},
            {"21930de65b31641f071b228f6e82cb", "Cryostasis: Sleep of Reason (D2D)"},
            {"b2eb51b963c309f73faf4e1fa2699", "Curse of the Pharaoh: Napoleon's Secret 2"},
            {"b328b691325153a58d470f00ad47d", "Curse of the Pharaoh: Tears of Sekhmet"},
            {"b44cad5d27c44322326c4fa9939ab", "Danse Macabre 5: Lethal Letters"},
            {"b333964ce159c5f89360eada779a3", "Danse Macabre 6: Ominous Obsession"},
            {"b44c6bc983ad998c5db6b4c33013b", "Danse Macabre 7: Florentine Elegy"},
            {"b404215e91813baaaa9a8cce2d0207", "Danse Macabre 8: Curse of the Banshee"},
            {"b453c5c774d1ab3c0593c1b68a2e1", "Danse Macabre 9: A Lover's Pledge"},
            {"f6a96685c4cb900f7da63bd83bf0d", "Dark Mysteries: The Soul Keeper"},
            {"b3a6526718756d090cd59d7a8ecf1", "Dark Parables: Ballad of Rapunzel"},
            {"b3c0955d359b05ac3f9d301b52c63", "Dark Parables: Goldilocks and the Fallen Star"}, // why is this here twice
            {"b3f089d3bb634ad10077f078d5c07", "Dark Parables: Requiem for the Forgotten Shadow"},
            {"b300db235d4f446950d7cd2a610b1", "Dark Parables: Rise of the Snow Queen"},
            {"b3ac27f14231049e8b91ba05b10e5", "Dark Parables: The Red Riding Hood Sisters"},
            {"b2f6db97b13f23805a828628dc981", "Dark Parables: The Thief and the Tinderbox"},
            {"b2ff63176d62ec97b43146813292b", "Dark Realm: Guardian of Flames"},
            {"b3f54137bfd5abe32dae9344e810d", "Dark Realm: Lord of the Winds"},
            {"b2f9d9075cce9c83cc48c6ac1614d", "Dark Romance: Curse of Bluebeard"},
            {"b3e95c03940589b3a21f96d83c5e7", "Dark Romance: Romeo and Juliet"},
            {"b38a3f5075aa2940c62b4b6ebf287", "Dark Romance: The Monster Within"},
            {"b3cb01960c0c48517ffb2f6503d61", "Dark Romance: Vampire In Love"},
            {"b3f8eb5d6ced866484bf157c24b27", "Dark Tales: Edgar Allan Poe's The Black Cat"},
            {"b4159a695e410856320fb0752aecf", "Dark Tales: Edgar Allan Poe's The Premature Burial"},
            {"b2f5070feaf9e2eec8ac683073977", "Dark Tales: Edgar Allan Poe's The Raven"},
            {"b46dd86a9d2a50b8552d6f74f4043", "Dark Tales: Edgar Allan Poe's The Tell-Tale Heart"},
            {"1711c65e7f5a81165597290ef1371d", "Disney/Pixar Toy Story 3 (Scandinavia)"},
            {"20b4748e0e820a3fe840ccf2a5b56f", "Divinity II ?"},
            {"42c6f0d67794e528e415a3ec1d91bb", "Divinity II: Flames of Vengeance (French)+Divinity II: Ego Draconis (USA, Europe)"}, // error?
            {"4726ba61b5a37713570bece23081b9", "Divinity II: Flames of Vengeance (Italian)"},
            {"106d01508e421b53547ec97de7fd89", "Divinity II: Flames of Vengeance (Spanish)"},
            {"7860e912f88586b38ca24d1b4505fd", "Divinity II: Flames of Vengeance (German, DVD)"},
            {"71cb27a0e66a08556dc5c273cabf5", "Divinity II: The Dragon Knight Saga (German, DVD)"},
            {"60be9006a6a23a5aa5b8e249374cff", "Divinity II: The Dragon Knight Saga (Hungary)"},
            {"4648b0e0a49537a92eace276d79693", "Drakensang: The River of Time (German, DVD)"},
            {"b2fc7124d05c8b96b0b880b425c8b", "Echoes of the Past: Royal House of Stone"},
            {"b3bcf47cbc273950ffa40312dcdfb", "Echoes of the Past: The Citadels of Time"},
            {"b3bba407a10674e0ed6391d14936d", "Echoes of the Past: The Revenge of the Witch"},
            {"1c90c0538ced3ed5cce0ef09572543", "Elven Legacy (D2D)"},
            {"61c88d738318d6dee22c98360d8efb", "Europa Universalis: Rome (D2D)"},
            {"71d795d253333e605690230fc09191", "Ex Machina"},
            {"45f4f622b0219c538807efef1b0ad", "F.E.A.R. 2: Project Origin (D2D)"},
            {"ae95c9cc412ef9247ea66badff93c7", "Fairytale Griddlers: Red Riding Hood Secret"},
            {"aec7356c5d226a174ce190f78d9919", "Fairytale Mosaics Beauty And The Beast"},
            {"ae876be80343b2c703e3e8e37e600f", "Fairytale Mosaics Cinderella 2"},
            {"bc224d856f5ee1e5058f50e24ebdb", "Far Cry 2 (China)"},
            {"f3f7e1fc6b6d98ef3b0bba1326e57", "Farm 2"},
            {"6e48f72e7b94b4a2a5f7a1c6a36b53", "Farm Frenzy: Ancient Rome"},
            {"6e0f2def0bf3f255add197a4c7b771", "Farm Frenzy: Gone Fishing"},
            {"6e2109b355824ccaa9cb0ee6c735f1", "Farm Frenzy: Heave Ho"},
            {"6e29a5dff8a335f3c41216a9496a61", "Farm Frenzy: Hurricane Season"},
            {"6e11b68cd5257a089d3bab648c71e3", "Farm Frenzy: Pizza Party"},
            {"b446dfe6f8faafd875d160d6bd633", "Farm Tribe"},
            {"b3ecec496c26b9fcb6771748f403b", "Farm Tribe 2"},
            {"cdd6ecc96b5f667ea216ac4db88bb", "Fate/Stay Night [Realta Nua] -Fate- (Japanese)"},
            {"d55bc3f4f9914035492ef7316b086b", "Fate/Stay Night [Realta Nua] -Heaven's Feel- (Japanese)"},
            {"3f460cb17efbad537b93dd9feffb9d", "Fate/Stay Night [Realta Nua] -Unlimited Blade Works- (Japanese)"},
            {"61524a79d032135331d8c04b16175f", "For The Glory: A Europa Universalis Game (D2D)"},
            {"b32603035154ea750c2c5fb61a0d1", "Grim Facade 3: The Cost of Jealousy"},
            {"b31fddd6b3ac7c0090defaddedc93", "Grim Facade 7: Monster in Disguise"},
            {"b3c351cfcad9431e2ea7bd82e6b33", "Harrowed Halls: Hell's Thistle"},
            {"b3202310f9322af100b732d5f2a95", "Harrowed Halls: Lakeview Lane"},
            {"b319ea0684f29b6ae54b57fa74181", "Haunted Halls: Fears from Childhood"},
            {"b33253e1a0c0c19145a6f05e2fe29", "Haunted Halls: Green Hills Sanitarium"},
            {"468252eb8f7a62a353559fc32cd6ef", "Hinterland"},
            {"2524f71ae22504f8254bb9909d7435", "Hugo - Ensimmaeiset Merkit (Finland)"},
            {"2d13a50989b3618b0759ef1796c5f3", "Immortal Cities: Children of the Nile (D2D)"},
            {"2c21ec36d1d305a39b279e16cf5f7d", "Imperium Romanum (D2D)"},
            {"4aca4f50f2db2e9671659e1b524a59", "Lara Croft: Tomb Raider - Legend (Japan)"},
            {"98cc4c6b4a6b0594312afb1b6e171", "Mahjong Garden Deluxe (American)"},
            {"8ec8350c9af57767c94c54321c1a8d", "Medieval II: Total War - Gold Edition (Germany)"},
            {"3ebf854b7121097f0a15f6133aec8b", "Men of War: Red Tide (D2D)"},
            {"105a0c2b24331e7d89a9faa583d167", "NBA 2K10 (D2D)"},
            {"3a83692b0b4db520ad5c21c924379", "NBA 2K10 (Metaboli)"},
            {"a4b2f0c977b30f036802f41bd57c3", "NBA 2K11 (D2D)"},
            {"3fe8e0758784da25d2f75c947c1c77", "NecroVisioN (D2D)"},
            {"65cf8514be1625c2b549b3ebcf819b", "NecroVisioN (GamersGate)"},
            {"677e16d4f095f8902ee2e0b4f564a1", "Operation Flashpoint: Dragon Rising (Metaboli)"},
            {"3a2523fb71f50d9d6120de66b2d9ff", "Overclocked (French)"},
            {"1847b086a7876dd4147145a65ff56f", "Pacific Storm (D2D)"},
            {"1781310ab0f6812c0bbf5b78853b03", "Pacific Storm (Steel Monsters GOLD)"},
            {"560bfaf1200fc40a69b8f464d4b84f", "Penumbra: Black Plague (D2D)"},
            {"2a95c4a9e992403d1148cda05099db", "Pro Evolution Soccer 2009 (Argentina)"},
            {"1de3566278ae184514537dfa35f9d7", "Poker for Dummies (USA)"},
            {"1960f4c7a20a9f7d5534d7d44608b5", "Restaurant Empire II (D2D)"},
            {"2f13462218e7944fc13a393c6b9e81", "Civilization IV: Beyond the Sword (D2D)"},
            {"169b6e99ef16ade9a5207863784653", "Sledgehammer"},
            {"7167e6a4609334d1aff1bfc218615", "Sniper: Ghost Warrior (D2D)"},
            {"1f90b7e650bee94722955b4253326d", "Space Empires V (D2D)"},
            {"25c01a2673d315d2de162dbf2ad26d", "Star Wars: The Force Unleashed - Ultimate Sith Edition (D2D)"},
            {"1bf1b25f7cef40ad473992545726f", "SunAge (D2D)"},
            {"5c5a98b313c4dfa3f8a54bd810ed85", "The Chronicles of Narnia: Prince Caspian (Scandinavia)"},
            {"13da59c479776357639048cb0a8969", "The Legend of Three Kingdoms VII (Sango 7) (Chinese Simplified)"},
            {"5701a872912e29dd47cf75e1a4dc3b", "The Sims 2: Double Deluxe"},
            {"ac4fb0b72e20b4c302d2a197006f5b", "The Sims 2: Fun with Pets Collection"},
            {"4e23a09cce521c129d2649a02dc493", "The Sims 2: University Life Collection"},
            {"5d147ad6fba459d1fa613b579a775", "The Spiderwick Chronicles (Germany)"},
            {"bf2cdb668fe45ecad53c9eec0cf9b", "Tomb Raider: Underworld (Japan)"},
            {"67780ff438e888f376de81eb7f9a63", "Victoria II (Japan)"},
            {"7eff99f8ff841104b736ea83edda83", "Xenus II: White Gold (SecuROM + StarForce)"},
            {"44aaf5ca46baee1bbdaab2811a67b9", "The Stalin Subway. (RUSSIA)"},
            {"6f8f34392fe59b2795d85fb062699", "The Stalin Subway: Red Veil (RUSSIA)"},
            {"4cee48b066359722b7fe418f09831f", "Morskaya upotia — Pathologic (RUSSIA)"},
            {"98cc7d1de5a027e665ca37df3b313d", "Petka 007: zoloto partii (RUSSIA)"},
            {"55c9b3644345bf9b64f5105e493fb", "Petka 4: Deni nezavisimosti (RUSSIA)"},
            {"8aa39cb69720e9ad209b8b036baf61", "Petka 5: konec igry (RUSSIA)"},
            {"12d362bad5115faffc78cd7d7c0841", "Petka 6: novaya realnosti (RUSSIA)"},
            {"21a15dce3ce00e6ab48712cd0f9cbb", "Petka 9: proletarsky glamour`(RUSSIA)"},
            {"a833f8e216bde3cbb0b230e851ef87", "Petka VIII: Pokorenie Rima (RUSSIA)"},
            {"3d672f2d97e2dc8ac19134bb9ea453", "Simbiont (MorphX). The Swarm (RUSSIA)"},
            {"1677493b5f0a6a175c4d5a120d043d", "Yaderniy titbit 2 (RUSSIA)"},
            {"1ce247466aa2a196503e0a5478783", "Divinity II: Ego Draconis (German)"},
        };
        
        /// <summary>
        /// Matches modulo of known PA-capable executables not in the 80_PA database.
        /// </summary>
        /// <remarks>If even a single PA-capable executable is known, it goes here.</remarks>
        private static readonly Dictionary<string, string> NotIn80 = new()
        {
            // Put modulo as key and name of game/application in value.
            // All entries should have a 29-character modulo as the key. If the key is 30 characters, remove
            // the first character and store the full 30 character key as the comment.
            // This is needed because some of the modulo values are up directly against other random data,
            // and this will at least ensure that no accidental misses occur.
            
            // For the listed reasons, the capability of these executables is not necessary to investigate.
            #region Capability Unnecessary
            
            // Executables confirmed to be PA-capable, just not in 80_pa yet. 
            #region Pending 
            { "1ecf89df85f715eebddb5d058a689", "The Witcher 2" }, // 61ecf89df85f715eebddb5d058a689
            { "b87f75c7ce81dbb076dc69f9c3923", "Tom Clancy's Ghost Recon Advanced Warfighter" }, // 61ecf89df85f715eebddb5d058a689

            #endregion
            
            // A small handful of late EA games use white label but have an origin login screen first. 
            // Currently not known whether these can be activated with PA until something like maxima launcher is functional.
            #region EA White Label
            { "46db7a796a17a125475f0232bf1fb", "FIFA 13" }, // 346db7a796a17a125475f0232bf1fb
            { "82a43e527334f3c82d7b600e6e3d3", "Syndicate" }, // 882a43e527334f3c82d7b600e6e3d3
            #endregion
            
            // Executables that are guaranteed to never be PA-capable (certain revocation executables and helper executables)
            #region Never Capable
            { "7383ab91ddc24d0f9ac5646a87e55", "Sacred 2 Game Server" }, // 27383ab91ddc24d0f9ac5646a87e55 - proper game executable has PA, this is just obfuscated/encrypted/whatever
            #endregion
            
            #endregion
            
            // SecuROM executables where no PA-capable executable with this modulo has been discovered yet.
            #region Currently Not Capable 
            { "ee6a70552eb7e69c1df8e51255c31", "Oxford Advanced Learner's Dictionary 9" }, 
            #endregion
            
        };
    }
}
