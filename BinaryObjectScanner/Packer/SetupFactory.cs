﻿using System;
using BinaryObjectScanner.Interfaces;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Packer
{
    // TODO: Add extraction, which is possible but the only tools available that can
    // do this seem to be Universal Extractor 2 and InstallExplorer (https://totalcmd.net/plugring/InstallExplorer.html)
    // https://raw.githubusercontent.com/wolfram77web/app-peid/master/userdb.txt
    public class SetupFactory : IExecutableCheck<PortableExecutable>
    {
        /// <inheritdoc/>
        public string? CheckExecutable(string file, PortableExecutable pex, bool includeDebug)
        {
            // Known to detect versions 7.0.5.1 - 9.1.0.0
            var name = pex.LegalCopyright;
            if (name.OptionalStartsWith("Setup Engine", StringComparison.OrdinalIgnoreCase))
                return $"Setup Factory {GetVersion(pex)}";

            name = pex.ProductName;
            if (name.OptionalStartsWith("Setup Factory", StringComparison.OrdinalIgnoreCase))
                return $"Setup Factory {GetVersion(pex)}";

            // Known to detect version 5.0.1 - 6.0.1.3
            name = pex.FileDescription;
            if (name.OptionalStartsWith("Setup Factory", StringComparison.OrdinalIgnoreCase))
                return $"Setup Factory {GetVersion(pex)}";

            // Longer version of the check that can be used if false positves become an issue:
            // "Setup Factory is a trademark of Indigo Rose Corporation"

            return null;
        }

        private static string GetVersion(PortableExecutable pex)
        {
            // Check the product version explicitly
            var version = pex.ProductVersion;
            if (!string.IsNullOrEmpty(version))
                return version!;

            // Check the internal versions
            version = pex.GetInternalVersion();
            if (!string.IsNullOrEmpty(version))
                return version!;

            return "(Unknown Version)";
        }
    }
}
