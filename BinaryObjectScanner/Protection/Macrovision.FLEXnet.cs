﻿using System;
using System.Collections.Generic;
using SabreTools.Matching;
using SabreTools.Matching.Paths;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Protection
{
    /// <summary>
    /// This is a placeholder FLEXnet (sub-Macrovision) specific functionality
    /// </summary>
    public partial class Macrovision
    {
        /// <inheritdoc cref="Interfaces.IExecutableCheck{T}.CheckExecutable(string, T, bool)"/>
        internal static string? FLEXnetCheckExecutable(string file, PortableExecutable pex, bool includeDebug)
        {
            var name = pex.ProductName;

            // Found in "IsSvcInstDanceEJay7.dll" in IA item "computer200709dvd" (Dance eJay 7).
            if (name.OptionalEquals("FLEXnet Activation Toolkit", StringComparison.OrdinalIgnoreCase))
                return "FLEXnet";

            // Found in "INSTALLS.EXE", "LMGR326B.DLL", "LMGRD.EXE", and "TAKEFIVE.EXE" in IA item "prog-17_202403".
            if (name.OptionalEquals("Globetrotter Software Inc lmgr326b Flexlm", StringComparison.OrdinalIgnoreCase))
                return $"FlexLM {pex.ProductVersion}";

            // Generic case to catch unknown versions.
            if (name.OptionalContains("Flexlm"))
                return "FlexLM (Unknown Version - Please report to us on GitHub)";

            name = pex.FileDescription;

            // Found in "INSTALLS.EXE", "LMGR326B.DLL", "LMGRD.EXE", and "TAKEFIVE.EXE" in IA item "prog-17_202403".
            if (name.OptionalEquals("lmgr326b", StringComparison.OrdinalIgnoreCase))
                return $"FlexLM {pex.ProductVersion}";

            name = pex.LegalTrademarks;

            // Found in "INSTALLS.EXE", "LMGR326B.DLL", "LMGRD.EXE", and "TAKEFIVE.EXE" in IA item "prog-17_202403".
            if (name.OptionalEquals("Flexible License Manager,FLEXlm,Globetrotter,FLEXID", StringComparison.OrdinalIgnoreCase))
                return $"FlexLM {pex.ProductVersion}";

            if (name.OptionalContains("FLEXlm"))
                return $"FlexLM {pex.ProductVersion}";

            name = pex.OriginalFilename;

            // Found in "INSTALLS.EXE", "LMGR326B.DLL", "LMGRD.EXE", and "TAKEFIVE.EXE" in IA item "prog-17_202403".
            // It isn't known why these various executables have the same original filename.
            if (name.OptionalEquals("lmgr326b.dll", StringComparison.OrdinalIgnoreCase))
                return $"FlexLM {pex.ProductVersion}";

            // Get the .data/DATA section strings, if they exist
            var strs = pex.GetFirstSectionStrings(".data") ?? pex.GetFirstSectionStrings("DATA");
            if (strs != null)
            {
                // Found in "FLEXLM.CPL", "INSTALLS.EXE", "LMGR326B.DLL", "LMGRD.EXE", and "TAKEFIVE.EXE" in IA item "prog-17_202403".
                if (strs.Exists(s => s.Contains("FLEXlm License Manager")))
                    return "FlexLM";
            }

            return null;
        }

        /// <inheritdoc cref="Interfaces.IPathCheck.CheckDirectoryPath(string, List{string})"/>
        internal static List<string> FLEXNetCheckDirectoryPath(string path, List<string>? files)
        {
            var matchers = new List<PathMatchSet>
            {
                // Found in IA item "prog-17_202403".
                new(new FilePathMatch("FlexLM-6.1F"), "FlexLM 6.1f"),
                new(new FilePathMatch("FlexLM"), "FlexLM"),
                new(new FilePathMatch("FLexLM_Licensing.wri"), "FlexLM"),
                new(new FilePathMatch("LMGR326B.DLL"), "FlexLM"),
                new(new FilePathMatch("FLEXLM.CPL"), "FlexLM"),
                new(new FilePathMatch("LMGRD.EXE"), "FlexLM"),
                new(new FilePathMatch("LMGRD95.EXE"), "FlexLM"),
                new(new FilePathMatch("LMUTIL.EXE"), "FlexLM"),
                new(new FilePathMatch("READFLEX.WRI"), "FlexLM"),
            };

            return MatchUtil.GetAllMatches(files, matchers, any: false);
        }

        /// <inheritdoc cref="Interfaces.IPathCheck.CheckFilePath(string)"/>
        internal static string? FLEXNetCheckFilePath(string path)
        {
            var matchers = new List<PathMatchSet>
            {
                // Found in IA item "prog-17_202403".
                new(new FilePathMatch("FlexLM-6.1F"), "FlexLM 6.1f"),
                new(new FilePathMatch("FlexLM"), "FlexLM"),
                new(new FilePathMatch("FLexLM_Licensing.wri"), "FlexLM"),
                new(new FilePathMatch("LMGR326B.DLL"), "FlexLM"),
                new(new FilePathMatch("FLEXLM.CPL"), "FlexLM"),
                new(new FilePathMatch("LMGRD.EXE"), "FlexLM"),
                new(new FilePathMatch("LMGRD95.EXE"), "FlexLM"),
                new(new FilePathMatch("LMUTIL.EXE"), "FlexLM"),
                new(new FilePathMatch("READFLEX.WRI"), "FlexLM"),
            };

            return MatchUtil.GetFirstMatch(path, matchers, any: true);
        }
    }
}
