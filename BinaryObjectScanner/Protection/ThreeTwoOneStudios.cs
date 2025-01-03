﻿using BinaryObjectScanner.Interfaces;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Protection
{
    public class ThreeTwoOneStudios : IExecutableCheck<PortableExecutable>
    {
        /// <inheritdoc/>
        public string? CheckExecutable(string file, PortableExecutable pex, bool includeDebug)
        {
            // Check the dialog box resources
            if (pex.FindDialogByTitle("321Studios Activation").Count > 0)
                return $"321Studios Online Activation";
            else if (pex.FindDialogByTitle("321Studios Phone Activation").Count > 0)
                return $"321Studios Online Activation";

            return null;
        }
    }
}
