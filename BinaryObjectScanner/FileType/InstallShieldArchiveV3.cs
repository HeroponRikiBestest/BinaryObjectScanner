﻿using System;
using System.IO;
using BinaryObjectScanner.Interfaces;

namespace BinaryObjectScanner.FileType
{
    /// <summary>
    /// InstallShield archive v3
    /// </summary>
    public class InstallShieldArchiveV3 : IExtractable
    {
        /// <inheritdoc/>
        public string? Extract(string file, bool includeDebug)
        {
            if (!File.Exists(file))
                return null;

            using var fs = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return Extract(fs, file, includeDebug);
        }

        /// <inheritdoc/>
        public string? Extract(Stream? stream, string file, bool includeDebug)
        {
            try
            {
                // Create a temp output directory
                string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
                Directory.CreateDirectory(tempPath);

                UnshieldSharp.Archive.InstallShieldArchiveV3 archive = new UnshieldSharp.Archive.InstallShieldArchiveV3(file);
                foreach (var cfile in archive.Files)
                {
                    try
                    {
                        string tempFile = Path.Combine(tempPath, cfile.Key);
                        var directoryName = Path.GetDirectoryName(tempFile);
                        if (directoryName != null && !Directory.Exists(directoryName))
                            Directory.CreateDirectory(directoryName);

                        byte[]? fileContents = archive.Extract(cfile.Key, out string? error);
                        if (fileContents == null || !string.IsNullOrEmpty(error))
                            continue;

                        using (FileStream fs = File.OpenWrite(tempFile))
                        {
                            fs.Write(fileContents, 0, fileContents.Length);
                        }
                    }
                    catch (Exception ex)
                    {
                        if (includeDebug) Console.WriteLine(ex);
                    }
                }

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
