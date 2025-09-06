﻿using System.Collections.Generic;
using System.Text;
using BinaryObjectScanner.Interfaces;
using SabreTools.Matching;
using SabreTools.Matching.Content;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Protection
{
    // TODO: Figure out how to get version numbers
    public class ActiveMARK : IContentCheck, IExecutableCheck<PortableExecutable>
    {
        /// <inheritdoc/>
        public string? CheckContents(string file, byte[] fileContent, bool includeDebug)
        {
            // TODO: Obtain a sample to find where this string is in a typical executable
            var contentMatchSets = new List<ContentMatchSet>
            {
                // " " + (char)0xC2 + (char)0x16 + (char)0x00 + (char)0xA8 + (char)0xC1 + (char)0x16 + (char)0x00 + (char)0xB8 + (char)0xC1 + (char)0x16 + (char)0x00 + (char)0x86 + (char)0xC8 + (char)0x16 + (char)0x00 + (char)0x9A + (char)0xC1 + (char)0x16 + (char)0x00 + (char)0x10 + (char)0xC2 + (char)0x16 + (char)0x00
                new(new byte?[]
                {
                    0x20, 0xC2, 0x16, 0x00, 0xA8, 0xC1, 0x16, 0x00,
                    0xB8, 0xC1, 0x16, 0x00, 0x86, 0xC8, 0x16, 0x00,
                    0x9A, 0xC1, 0x16, 0x00, 0x10, 0xC2, 0x16, 0x00
                }, "ActiveMARK 5 (Unconfirmed - Please report to us on Github)"),
            };

            return MatchUtil.GetFirstMatch(file, fileContent, contentMatchSets, includeDebug);
        }

        /// <inheritdoc/>
        public string? CheckExecutable(string file, PortableExecutable pex, bool includeDebug)
        {
            // Get the entry point data, if it exists
            if (pex.EntryPointData != null)
            {
                // Found in "Zuma.exe"
                if (pex.EntryPointData.StartsWith(new byte?[] { 0x89, 0x25, 0x04, 0xF0, 0x86, 0x00, 0x68, 0x30 }))
                    return "ActiveMark v5.3.1078 (Packer Version)";
            }

            // Get the .data section strings, if they exist
            var strs = pex.GetLastSectionStrings(".data");
            if (strs != null)
            {
                if (strs.Exists(s => s.Contains("MPRMMGVA"))
                    && strs.Exists(s => s.Contains("This application cannot run with an active debugger in memory.")))
                {
                    return "ActiveMARK 6.x";
                }
            }

            // Get "REGISTRY, AMINTERNETPROTOCOL" resource items
            var resources = pex.FindResourceByNamedType("REGISTRY, AMINTERNETPROTOCOL");
            if (resources.Count > 0)
            {
                bool match = resources
                    .ConvertAll(r => r == null ? string.Empty : Encoding.ASCII.GetString(r))
                    .FindIndex(r => r.Contains("ActiveMARK")) > -1;
                if (match)
                    return "ActiveMARK";
            }

            // Get the overlay data, if it exists
            if (pex.OverlayStrings != null)
            {
                if (pex.OverlayStrings.Exists(s => s.Contains("TMSAMVOH")))
                    return "ActiveMARK";
            }

            // Get the last .bss section strings, if they exist
            strs = pex.GetLastSectionStrings(".bss");
            if (strs != null)
            {
                if (strs.Exists(s => s.Contains("TMSAMVOF")))
                    return "ActiveMARK";
            }

            return null;
        }
    }
}
