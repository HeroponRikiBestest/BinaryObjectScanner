using System;
using System.IO;
using BinaryObjectScanner.Interfaces;

namespace BinaryObjectScanner.FileType
{
    /// <summary>
    /// Half-Life Texture Package File
    /// </summary>
    public class WAD3 : IExtractable
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
            try
            {
                // Create the wrapper
                var wad = SabreTools.Serialization.Wrappers.WAD3.Create(stream);
                if (wad == null)
                    return false;

                // Loop through and extract all files
                Directory.CreateDirectory(outDir);
                ExtractAllLumps(wad, outDir);

                return true;
            }
            catch (Exception ex)
            {
                if (includeDebug) Console.WriteLine(ex);
                return false;
            }
        }

        /// <summary>
        /// Extract all lumps from the WAD3 to an output directory
        /// </summary>
        /// <param name="outputDirectory">Output directory to write to</param>
        /// <returns>True if all lumps extracted, false otherwise</returns>
        public static bool ExtractAllLumps(SabreTools.Serialization.Wrappers.WAD3 item, string outputDirectory)
        {
            // If we have no lumps
            if (item.Model.DirEntries == null || item.Model.DirEntries.Length == 0)
                return false;

            // Loop through and extract all lumps to the output
            bool allExtracted = true;
            for (int i = 0; i < item.Model.DirEntries.Length; i++)
            {
                allExtracted &= ExtractLump(item, i, outputDirectory);
            }

            return allExtracted;
        }

        /// <summary>
        /// Extract a lump from the WAD3 to an output directory by index
        /// </summary>
        /// <param name="index">Lump index to extract</param>
        /// <param name="outputDirectory">Output directory to write to</param>
        /// <returns>True if the lump extracted, false otherwise</returns>
        public static bool ExtractLump(SabreTools.Serialization.Wrappers.WAD3 item, int index, string outputDirectory)
        {
            // If we have no lumps
            if (item.Model.DirEntries == null || item.Model.DirEntries.Length == 0)
                return false;

            // If the lumps index is invalid
            if (index < 0 || index >= item.Model.DirEntries.Length)
                return false;

            // Get the lump
            var lump = item.Model.DirEntries[index];
            if (lump == null)
                return false;

            // Read the data -- TODO: Handle uncompressed lumps (see BSP.ExtractTexture)
            var data = item.ReadFromDataSource((int)lump.Offset, (int)lump.Length);
            if (data == null)
                return false;

            // Create the filename
            string filename = $"{lump.Name}.lmp";

            // If we have an invalid output directory
            if (string.IsNullOrEmpty(outputDirectory))
                return false;

            // Create the full output path
            filename = Path.Combine(outputDirectory, filename);

            // Ensure the output directory is created
            var directoryName = Path.GetDirectoryName(filename);
            if (directoryName != null)
                Directory.CreateDirectory(directoryName);

            // Try to write the data
            try
            {
                // Open the output file for writing
                using Stream fs = File.OpenWrite(filename);
                fs.Write(data, 0, data.Length);
            }
            catch
            {
                return false;
            }

            return true;
        }
    }
}
