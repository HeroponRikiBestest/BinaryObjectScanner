﻿using BinaryObjectScanner.Interfaces;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Packer
{
    // TODO: Better version detection - https://raw.githubusercontent.com/wolfram77web/app-peid/master/userdb.txt
    // TODO: Add extraction
    public class PECompact : IExtractableExecutable<PortableExecutable>
    {
        /// <inheritdoc/>
        public string? CheckExecutable(string file, PortableExecutable pex, bool includeDebug)
        {
            // 0x4F434550 is "PECO"
            if (pex.Model.COFFFileHeader?.PointerToSymbolTable == 0x4F434550)
                return "PE Compact v1.x";

            // TODO: Get more granular version detection. PiD is somehow able to detect version ranges based
            // on the data in the file. This may be related to information in other fields

            // Get the pec1 section, if it exists
            if (pex.ContainsSection("pec1", exact: true))
                return "PE Compact v1.x";

            // Get the PEC2 section, if it exists -- TODO: Verify this comment since it's pulling the .text section
            var textSection = pex.GetFirstSection(".text", exact: true);
            if (textSection?.PointerToRelocations == 0x32434550)
            {
                if (textSection.PointerToLinenumbers != 0)
                    return $"PE Compact v{textSection.PointerToLinenumbers} (internal version)";

                return "PE Compact v2.x (or newer)";
            }

            return null;
        }

        /// <inheritdoc/>
        public bool Extract(string file, PortableExecutable pex, string outDir, bool includeDebug)
        {
            return false;
        }
    }
}
