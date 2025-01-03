﻿using BinaryObjectScanner.Interfaces;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Packer
{
    // TODO: Add extraction
    public class DotFuscator : IExtractableExecutable<PortableExecutable>
    {
        /// <inheritdoc/>
        public string? CheckExecutable(string file, PortableExecutable pex, bool includeDebug)
        {
            // Get the .text section strings, if they exist
            var strs = pex.GetFirstSectionStrings(".text");
            if (strs != null)
            {
                if (strs.Exists(s => s.Contains("DotfuscatorAttribute")))
                    return "dotFuscator";
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
