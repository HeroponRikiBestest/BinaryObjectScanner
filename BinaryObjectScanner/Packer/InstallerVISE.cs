using System.Collections.Generic;
using System.IO;
using System.Linq;
using BinaryObjectScanner.Interfaces;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Packer
{
    // TODO: Add extraction - https://github.com/Bioruebe/UniExtract2
    // https://raw.githubusercontent.com/wolfram77web/app-peid/master/userdb.txt
    public class InstallerVISE : IExtractable, IPortableExecutableCheck
    {
        //TODO: Add exact version detection for Windows builds, make sure versions before 3.X are detected as well, and detect the Mac builds.
        /// <inheritdoc/>
#if NET48
        public string CheckPortableExecutable(string file, PortableExecutable pex, bool includeDebug)
#else
        public string? CheckPortableExecutable(string file, PortableExecutable pex, bool includeDebug)
#endif
        {
            // Get the sections from the executable, if possible
            var sections = pex.Model.SectionTable;
            if (sections == null)
                return null;

            // Get the .data/DATA section strings, if they exist
            var strs = pex.GetFirstSectionStrings(".data") ?? pex.GetFirstSectionStrings("DATA");
            if (strs != null)
            {
                if (strs.Any(s => s.Contains("ViseMain")))
                    return "Installer VISE";
            }
            
            return null;
        }

        /// <inheritdoc/>
#if NET48
        public string Extract(string file, bool includeDebug)
#else
        public string? Extract(string file, bool includeDebug)
#endif
        {
            if (!File.Exists(file))
                return null;

            using (var fs = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                return Extract(fs, file, includeDebug);
            }
        }

        /// <inheritdoc/>
#if NET48
        public string Extract(Stream stream, string file, bool includeDebug)
#else
        public string? Extract(Stream stream, string file, bool includeDebug)
#endif
        {
            return null;
        }
    }
}