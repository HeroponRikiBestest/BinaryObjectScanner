﻿using System;
using System.IO;
using SabreTools.IO.Extensions;
using SabreTools.Matching;

namespace BinaryObjectScanner.FileType
{
    /// <summary>
    /// Link Data Security encrypted file
    /// </summary>
    public class LDSCRYPT : DetectableBase
    {
        /// <inheritdoc/>
        public override string? Detect(Stream stream, string file, bool includeDebug)
        {
            try
            {
                byte[] magic = stream.ReadBytes(16);
                if (magic.StartsWith(new byte?[] { 0x4C, 0x44, 0x53, 0x43, 0x52, 0x59, 0x50, 0x54 }))
                    return "Link Data Security encrypted file";
            }
            catch (Exception ex)
            {
                if (includeDebug) Console.Error.WriteLine(ex);
            }

            return null;
        }
    }
}
