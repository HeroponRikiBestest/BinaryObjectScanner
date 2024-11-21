using System;
using System.IO;
using System.Linq;
using BinaryObjectScanner.Interfaces;
using SabreTools.Matching;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Packer
{
    /// <summary>
    /// Though not technically a packer, this detection is for any executables that include
    /// archives in their resources in some uncompressed manner to be used at runtime.
    /// </summary>
    public class EmbeddedArchive : IExtractableExecutable<PortableExecutable>
    {
        /// <inheritdoc/>
        public string? CheckExecutable(string file, PortableExecutable pex, bool includeDebug)
        {
            // Get the sections from the executable, if possible
            var sections = pex.Model.SectionTable;
            if (sections == null)
                return null;

            // Get the resources that have a PKZIP signature
            if (pex.ResourceData != null
                && pex.ResourceData.Values.Any(v => v is byte[] ba
                    && ba.StartsWith(SabreTools.Models.PKZIP.Constants.LocalFileHeaderSignatureBytes)))
            {
                return "Embedded Archive";
            }

            return null;
        }

        /// <inheritdoc/>
        public bool Extract(string file, PortableExecutable pex, string outDir, bool includeDebug)
        {
            try
            {
                // If there are no resources
                if (pex.ResourceData == null)
                    return false;

                // Get the resources that have a PKZIP signature
                var resources = pex.ResourceData.Values
                    .Where(v => v != null && v is byte[])
                    .Select(v => v as byte[])
                    .Where(b => b != null && b.StartsWith(SabreTools.Models.PKZIP.Constants.LocalFileHeaderSignatureBytes))
                    .ToList();

                for (int i = 0; i < resources.Count; i++)
                {
                    try
                    {
                        // Get the resource data
                        var data = resources[i];
                        if (data == null)
                            continue;

                        // Create the temp filename
                        string tempFile = $"embedded_resource_{i}.zip";
                        tempFile = Path.Combine(outDir, tempFile);
                        var directoryName = Path.GetDirectoryName(tempFile);
                        if (directoryName != null && !Directory.Exists(directoryName))
                            Directory.CreateDirectory(directoryName);

                        // Write the resource data to a temp file
                        using var tempStream = File.Open(tempFile, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
                        tempStream?.Write(data, 0, data.Length);
                    }
                    catch (Exception ex)
                    {
                        if (includeDebug) Console.WriteLine(ex);
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                if (includeDebug) Console.WriteLine(ex);
                return false;
            }
        }
    }
}