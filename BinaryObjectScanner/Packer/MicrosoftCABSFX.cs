using System;
using System.Linq;
using BinaryObjectScanner.Interfaces;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Packer
{
    // TODO: Add extraction, which should be possible with LibMSPackN, but it refuses to extract due to SFX files lacking the typical CAB identifiers.
    // https://raw.githubusercontent.com/wolfram77web/app-peid/master/userdb.txt
    public class MicrosoftCABSFX : IExecutableCheck<PortableExecutable>, IExtractableExecutable<PortableExecutable>
    {
        /// <inheritdoc/>
        public string? CheckExecutable(string file, PortableExecutable pex, bool includeDebug)
        {
            // Get the sections from the executable, if possible
            var sections = pex.Model.SectionTable;
            if (sections == null)
                return null;

            var name= pex.InternalName;
            if (name?.Equals("Wextract", StringComparison.OrdinalIgnoreCase) == true)
                return $"Microsoft CAB SFX {GetVersion(pex)}";

            name = pex.OriginalFilename;
            if (name?.Equals("WEXTRACT.EXE", StringComparison.OrdinalIgnoreCase) == true)
                return $"Microsoft CAB SFX {GetVersion(pex)}";

            // Get the .data/DATA section strings, if they exist
            var strs = pex.GetFirstSectionStrings(".data") ?? pex.GetFirstSectionStrings("DATA");
            if (strs != null)
            {
                if (strs.Any(s => s.Contains("wextract_cleanup")))
                    return $"Microsoft CAB SFX {GetVersion(pex)}";
            }

            // Get the .text section strings, if they exist
            strs = pex.GetFirstSectionStrings(".text");
            if (strs != null)
            {
                // This detects a different but similar type of SFX that uses Microsoft CAB files.
                // Further research is needed to see if it's just a different version or entirely separate.
                if (strs.Any(s => s.Contains("MSCFu")))
                    return $"Microsoft CAB SFX {GetVersion(pex)}";
            }

            return null;
        }

        /// <inheritdoc/>
        public bool Extract(string file, PortableExecutable pex, string outDir, bool includeDebug)
        {
            return false;
        }

        private string GetVersion(PortableExecutable pex)
        {
            // Check the internal versions
            var version = pex.GetInternalVersion();
            if (!string.IsNullOrEmpty(version))
                return $"v{version}";

            return string.Empty;
        }
    }
}
