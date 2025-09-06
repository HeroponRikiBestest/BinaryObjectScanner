using System;
using System.IO;
using BinaryObjectScanner.Interfaces;

namespace BinaryObjectScanner.FileType
{
    /// <summary>
    /// AACS media key block
    /// </summary>
    public class AACSMediaKeyBlock : IDetectable<SabreTools.Serialization.Wrappers.AACSMediaKeyBlock>
    {
        /// <inheritdoc/>
        public string? Detect(string file, bool includeDebug)
        {
            if (!File.Exists(file))
                return null;

            using var fs = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return Detect(fs, file, includeDebug);
        }

        /// <inheritdoc/>
        public string? Detect(Stream stream, string file, bool includeDebug)
        {
            // Create the wrapper
            var mkb = SabreTools.Serialization.Wrappers.AACSMediaKeyBlock.Create(stream);
            if (mkb == null)
                return null;

            // Derive the version, if possible
            var typeAndVersion = Array.Find(mkb.Records ?? [], r => r?.RecordType == SabreTools.Models.AACS.RecordType.TypeAndVersion);
            if (typeAndVersion == null)
                return "AACS (Unknown Version)";
            else
                return $"AACS {(typeAndVersion as SabreTools.Models.AACS.TypeAndVersionRecord)?.VersionNumber}";
        }
    }
}
