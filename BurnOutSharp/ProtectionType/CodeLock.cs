﻿using System.Collections.Generic;
using System.Linq;
using System.Text;
using BurnOutSharp.ExecutableType.Microsoft;
using BurnOutSharp.Matching;

namespace BurnOutSharp.ProtectionType
{
    public class CodeLock : IContentCheck
    {
        /// <inheritdoc/>
        public string CheckContents(string file, byte[] fileContent, bool includeDebug, PortableExecutable pex, NewExecutable nex)
        {
            // Get the sections from the executable, if possible
            var sections = pex?.SectionTable;
            if (sections == null)
                return null;
            
            // If there are more than 2 icd-prefixed sections, then we have a match
            int icdSectionCount = sections.Count(s => Encoding.ASCII.GetString(s.Name).StartsWith("icd"));
            if (icdSectionCount >= 2)
                return "CodeLock";
            
            // TODO: Obtain a sample to find where this string is in a typical executable
            var contentMatchSets = new List<ContentMatchSet>
            {
                // CODE-LOCK.OCX
                new ContentMatchSet(new byte?[]
                {
                    0x43, 0x4F, 0x44, 0x45, 0x2D, 0x4C, 0x4F, 0x43,
                    0x4B, 0x2E, 0x4F, 0x43, 0x58
                }, "CodeLock"),
            };
            
            return MatchUtil.GetFirstMatch(file, fileContent, contentMatchSets, includeDebug);
        }
    }
}
