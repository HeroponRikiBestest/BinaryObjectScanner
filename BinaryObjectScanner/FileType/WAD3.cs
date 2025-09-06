using System.IO;
using BinaryObjectScanner.Interfaces;

namespace BinaryObjectScanner.FileType
{
    /// <summary>
    /// Half-Life Texture Package File
    /// </summary>
    public class WAD3 : IExtractable<SabreTools.Serialization.Wrappers.WAD3>
    {
        /// <inheritdoc/>
        public bool Extract(string file, string outDir, bool includeDebug)
        {
            if (!File.Exists(file))
                return false;

            using var fs = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return Extract(fs, file, outDir, includeDebug);
        }

        /// <inheritdoc/>
        public bool Extract(Stream? stream, string file, string outDir, bool includeDebug)
        {
            // Create the wrapper
            var wad = SabreTools.Serialization.Wrappers.WAD3.Create(stream);
            if (wad == null)
                return false;

            // Loop through and extract all files
            Directory.CreateDirectory(outDir);
            wad.Extract(outDir, includeDebug);

            return true;
        }
    }
}
