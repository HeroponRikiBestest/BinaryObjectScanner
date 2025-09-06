﻿using System;
using System.Collections.Generic;
using System.IO;
using BinaryObjectScanner.Interfaces;
using SabreTools.Matching;
using SabreTools.Matching.Paths;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Protection
{
    // Note that this set of checks also contains "Stardock Product Activation"
    // This is intentional, as that protection is highly related to Impulse Reactor
    public class ImpulseReactor : IExecutableCheck<PortableExecutable>, IPathCheck
    {
        /// <inheritdoc/>
        public string? CheckExecutable(string file, PortableExecutable pex, bool includeDebug)
        {
            var name = pex.FileDescription;
            if (name.OptionalContains("ImpulseReactor Dynamic Link Library"))
                return $"Impulse Reactor Core Module {pex.GetInternalVersion()}";

            name = pex.ProductName;
            if (name.OptionalContains("ImpulseReactor Dynamic Link Library"))
                return $"Impulse Reactor Core Module {pex.GetInternalVersion()}";

            name = pex.OriginalFilename;
            if (name.OptionalContains("ReactorActivate.exe"))
                return $"Stardock Product Activation {pex.GetInternalVersion()}";

            // TODO: Check for CVP* instead?
            bool containsCheck = false;
            if (pex.Model.ExportTable?.ExportNameTable?.Strings != null)
                containsCheck = Array.Exists(pex.Model.ExportTable.ExportNameTable.Strings, s => s.OptionalStartsWith("CVPInitializeClient"));

            // Get the .rdata section strings, if they exist
            bool containsCheck2 = false;
            var strs = pex.GetFirstSectionStrings(".rdata");
            if (strs != null)
            {
                containsCheck2 = strs.Exists(s => s.EndsWith("ATTLIST"))
                    && strs.Exists(s => s.Equals("ELEMENT"))
                    && strs.Exists(s => s.StartsWith("NOTATION"));
            }

            if (containsCheck && containsCheck2)
                return $"Impulse Reactor Core Module {pex.GetInternalVersion()}";
            else if (containsCheck && !containsCheck2)
                return $"Impulse Reactor";

            return null;
        }

        /// <inheritdoc/>
        public List<string> CheckDirectoryPath(string path, List<string>? files)
        {
            var matchers = new List<PathMatchSet>
            {
                new(new FilePathMatch("ImpulseReactor.dll"), GetInternalVersion, "Impulse Reactor Core Module"),
                new(new FilePathMatch("ReactorActivate.exe"), GetInternalVersion, "Stardock Product Activation"),
            };

            return MatchUtil.GetAllMatches(files, matchers, any: true);
        }

        /// <inheritdoc/>
        public string? CheckFilePath(string path)
        {
            var matchers = new List<PathMatchSet>
            {
                new(new FilePathMatch("ImpulseReactor.dll"), GetInternalVersion, "Impulse Reactor Core Module"),
                new(new FilePathMatch("ReactorActivate.exe"), GetInternalVersion, "Stardock Product Activation"),
            };

            return MatchUtil.GetFirstMatch(path, matchers, any: true);
        }

        private string? GetInternalVersion(string firstMatchedString, List<string>? files)
        {
            try
            {
                using Stream fileStream = File.Open(firstMatchedString, FileMode.Open, FileAccess.Read, FileShare.Read);
                var pex = PortableExecutable.Create(fileStream);
                return pex?.GetInternalVersion() ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}
