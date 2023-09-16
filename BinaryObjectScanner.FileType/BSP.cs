using System;
using System.IO;
using BinaryObjectScanner.Interfaces;
using BinaryObjectScanner.Wrappers;

namespace BinaryObjectScanner.FileType
{
    /// <summary>
    /// Half-Life Level
    /// </summary>
    public class BSP : IExtractable
    {
        /// <inheritdoc/>
        public string Extract(string file, bool includeDebug)
        {
            if (!File.Exists(file))
                return null;

            using (var fs = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                return Extract(fs, file, includeDebug);
            }
        }

        /// <inheritdoc/>
        public string Extract(Stream stream, string file, bool includeDebug)
        {
            try
            {
                // Create the wrapper
                SabreTools.Serialization.Wrappers.BSP bsp = SabreTools.Serialization.Wrappers.BSP.Create(stream);
                if (bsp == null)
                    return null;

                // Create a temp output directory
                string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
                Directory.CreateDirectory(tempPath);

                // Loop through and extract all files
                bsp.ExtractAllLumps(tempPath);
                bsp.ExtractAllTextures(tempPath);

                return tempPath;
            }
            catch (Exception ex)
            {
                if (includeDebug) Console.WriteLine(ex);
                return null;
            }
        }
    }
}
