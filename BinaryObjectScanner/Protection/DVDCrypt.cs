﻿using System.Collections.Generic;
using BinaryObjectScanner.Interfaces;
using SabreTools.IO;
using SabreTools.IO.Matching;

namespace BinaryObjectScanner.Protection
{
    public class DVDCrypt : IPathCheck
    {
        /// <inheritdoc/>
        public List<string> CheckDirectoryPath(string path, List<string>? files)
        {
            var matchers = new List<PathMatchSet>
            {
                new(new FilePathMatch("DvdCrypt.pdb"), "DVD Crypt (Unconfirmed - Please report to us on Github)"),
            };

            return MatchUtil.GetAllMatches(files, matchers, any: true);
        }

        /// <inheritdoc/>
        public string? CheckFilePath(string path)
        {
            var matchers = new List<PathMatchSet>
            {
                new(new FilePathMatch("DvdCrypt.pdb"), "DVD Crypt (Unconfirmed - Please report to us on Github)"),
            };

            return MatchUtil.GetFirstMatch(path, matchers, any: true);
        }
    }
}
