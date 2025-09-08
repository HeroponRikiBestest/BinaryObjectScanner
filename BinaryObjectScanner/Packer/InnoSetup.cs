﻿using System.Collections.Generic;
using BinaryObjectScanner.Interfaces;
using SabreTools.Matching;
using SabreTools.Matching.Content;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Packer
{
    // TODO: Add extraction - https://github.com/dscharrer/InnoExtract
    // https://raw.githubusercontent.com/wolfram77web/app-peid/master/userdb.txt
    public class InnoSetup : IExecutableCheck<NewExecutable>, IExecutableCheck<PortableExecutable>
    {
        /// <inheritdoc/>
        public string? CheckExecutable(string file, NewExecutable exe, bool includeDebug)
        {
            // Check for "Inno" in the reserved words
            var reserved2 = exe.Model.Stub?.Header?.Reserved2;
            if (reserved2 != null && reserved2.Length > 5)
            {
                if (reserved2[4] == 0x6E49 && reserved2[5] == 0x6F6E)
                {
                    string version = GetOldVersion(file, exe);
                    if (!string.IsNullOrEmpty(version))
                        return $"Inno Setup {version}";

                    return "Inno Setup (Unknown Version)";
                }
            }

            return null;
        }

        /// <inheritdoc/>
        public string? CheckExecutable(string file, PortableExecutable exe, bool includeDebug)
        {
            // Get the .data/DATA section strings, if they exist
            var strs = exe.GetFirstSectionStrings(".data") ?? exe.GetFirstSectionStrings("DATA");
            if (strs != null)
            {
                var str = strs.Find(s => s.StartsWith("Inno Setup Setup Data"));
                if (str != null)
                {
                    return str.Replace("Inno Setup Setup Data", "Inno Setup")
                        .Replace("(u)", "[Unicode]")
                        .Replace("(", string.Empty)
                        .Replace(")", string.Empty)
                        .Replace("[Unicode]", "(Unicode)");
                }
            }

            return null;
        }

        private static string GetOldVersion(string file, NewExecutable exe)
        {
            // Notes:
            // Look into `SETUPLDR` in the resident-name table
            // Look into `SETUPLDR.EXE` in the nonresident-name table

            // TODO: Don't read entire file
            // TODO: Only 64 bytes at the end of the file is needed

            byte[]? data = exe.ReadArbitraryRange();
            if (data == null)
                return "Unknown 1.X";

            var matchers = new List<ContentMatchSet>
                {
                    // "rDlPtS02" + (char)0x87 + "eVx"
                    new(new byte?[] { 0x72, 0x44, 0x6C, 0x50, 0x74, 0x53, 0x30, 0x32, 0x87, 0x65, 0x56, 0x78 }, "1.2.16 or earlier"),
                };

            return MatchUtil.GetFirstMatch(file, data, matchers, false) ?? "Unknown 1.X";
        }
    }
}
