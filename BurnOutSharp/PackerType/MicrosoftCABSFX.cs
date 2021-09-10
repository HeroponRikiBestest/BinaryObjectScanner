using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using BurnOutSharp.ExecutableType.Microsoft;
using BurnOutSharp.Matching;
using BurnOutSharp.Tools;

namespace BurnOutSharp.PackerType
{
    // TODO: Add extraction, which should be possible with LibMSPackN, but it refuses to extract due to SFX files lacking the typical CAB identifiers.
    public class MicrosoftCABSFX : IContentCheck, IScannable
    {
        /// <inheritdoc/>
        public bool ShouldScan(byte[] magic) => true;

        /// <inheritdoc/>
        public List<ContentMatchSet> GetContentMatchSets() => null;

        /// <inheritdoc/>
        public string CheckContents(string file, byte[] fileContent, bool includeDebug = false)
        {
            // TODO: Implement resource finding instead of using the built in methods
            // Assembly information lives in the .rsrc section
            // I need to find out how to navigate the resources in general
            // as well as figure out the specific resources for both
            // file info and MUI (XML) info. Once I figure this out,
            // that also opens the doors to easier assembly XML checks.

            var fvinfo = Utilities.GetFileVersionInfo(file);

            string name = fvinfo?.InternalName?.Trim();
            if (!string.IsNullOrWhiteSpace(name) && name.Equals("Wextract", StringComparison.OrdinalIgnoreCase))
            {
                string version = GetVersion(file, fileContent, null);
                if (!string.IsNullOrWhiteSpace(version))
                    return $"Microsoft CAB SFX v{Utilities.GetFileVersion(fileContent)}";

                return "Microsoft CAB SFX";
            }

            name = fvinfo?.OriginalFilename?.Trim();
            if (!string.IsNullOrWhiteSpace(name) && name.Equals("WEXTRACT.EXE", StringComparison.OrdinalIgnoreCase))
            {
                string version = GetVersion(file, fileContent, null);
                if (!string.IsNullOrWhiteSpace(version))
                    return $"Microsoft CAB SFX v{Utilities.GetFileVersion(fileContent)}";

                return "Microsoft CAB SFX";
            }

            // Get the sections from the executable, if possible
            PortableExecutable pex = PortableExecutable.Deserialize(fileContent, 0);
            var sections = pex?.SectionTable;
            if (sections == null)
                return null;

            // Get the .data section, if it exists
            var dataSection = sections.FirstOrDefault(s => Encoding.ASCII.GetString(s.Name).StartsWith(".data"));
            if (dataSection != null)
            {
                int sectionAddr = (int)dataSection.PointerToRawData;
                int sectionEnd = sectionAddr + (int)dataSection.VirtualSize;
                var matchers = new List<ContentMatchSet>
                {
                    // wextract_cleanup
                    new ContentMatchSet(
                        new ContentMatch(new byte?[]
                        {
                            0x77, 0x65, 0x78, 0x74, 0x72, 0x61, 0x63, 0x74, 
                            0x5F, 0x63, 0x6C, 0x65, 0x61, 0x6E, 0x75, 0x70,
                        }, start: sectionAddr, end: sectionEnd),
                    GetVersion, "Microsoft CAB SFX"),
                };

                string match = MatchUtil.GetFirstMatch(file, fileContent, matchers, includeDebug);
                if (!string.IsNullOrWhiteSpace(match))
                    return match;
            }
            
            // Get the .rsrc section, if it exists
            var rsrcSection = sections.FirstOrDefault(s => Encoding.ASCII.GetString(s.Name).StartsWith(".rsrc"));
            if (rsrcSection != null)
            {
                int sectionAddr = (int)rsrcSection.PointerToRawData;
                int sectionEnd = sectionAddr + (int)rsrcSection.VirtualSize;
                var matchers = new List<ContentMatchSet>
                {
                    // W + (char)0x00 + e + (char)0x00 + x + (char)0x00 + t + (char)0x00 + r + (char)0x00 + a + (char)0x00 + c + (char)0x00 + t + (char)0x00
                    new ContentMatchSet(
                        new ContentMatch(new byte?[]
                        {
                            0x57, 0x00, 0x65, 0x00, 0x78, 0x00, 0x74, 0x00, 
                            0x72, 0x00, 0x61, 0x00, 0x63, 0x00, 0x74, 0x00,
                        }, start: sectionAddr, end: sectionEnd),
                    GetVersion, "Microsoft CAB SFX"),

                    // W + (char)0x00 + E + (char)0x00 + X + (char)0x00 + T + (char)0x00 + R + (char)0x00 + A + (char)0x00 + C + (char)0x00 + T + (char)0x00 + . + (char)0x00 + E + (char)0x00 + X + (char)0x00 + E + (char)0x00
                    new ContentMatchSet(
                        new ContentMatch(new byte?[]
                        {
                            0x57, 0x00, 0x45, 0x00, 0x58, 0x00, 0x54, 0x00,
                            0x52, 0x00, 0x41, 0x00, 0x43, 0x00, 0x54, 0x00,
                            0x2E, 0x00, 0x45, 0x00, 0x58, 0x00, 0x45, 0x00,
                        }, start: sectionAddr, end: sectionEnd),
                    GetVersion, "Microsoft CAB SFX"),
                };

                string match = MatchUtil.GetFirstMatch(file, fileContent, matchers, includeDebug);
                if (!string.IsNullOrWhiteSpace(match))
                    return match;
            }

            // Get the .text section, if it exists
            var textSection = sections.FirstOrDefault(s => Encoding.ASCII.GetString(s.Name).StartsWith(".text"));
            if (textSection != null)
            {
                int sectionAddr = (int)textSection.PointerToRawData;
                int sectionEnd = sectionAddr + (int)textSection.VirtualSize;
                var matchers = new List<ContentMatchSet>
                {
                    /* This detects a different but similar type of SFX that uses Microsoft CAB files.
                       Further research is needed to see if it's just a different version or entirely separate. */
                    // MSCFu
                    new ContentMatchSet(
                        new ContentMatch(new byte?[] { 0x4D, 0x53, 0x43, 0x46, 0x75 }, start: sectionAddr, end: sectionEnd),
                    GetVersion, "Microsoft CAB SFX"),
                };

                string match = MatchUtil.GetFirstMatch(file, fileContent, matchers, includeDebug);
                if (!string.IsNullOrWhiteSpace(match))
                    return match;
            }

            return null;
        }

        /// <inheritdoc/>
        public ConcurrentDictionary<string, ConcurrentQueue<string>> Scan(Scanner scanner, string file)
        {
            if (!File.Exists(file))
                return null;

            using (var fs = File.OpenRead(file))
            {
                return Scan(scanner, fs, file);
            }
        }

        /// <inheritdoc/>
        public ConcurrentDictionary<string, ConcurrentQueue<string>> Scan(Scanner scanner, Stream stream, string file)
        {
            return null;
        }

        // This method of version detection is suboptimal because the version is sometimes the version of the included software, not the SFX itself.
        public static string GetVersion(string file, byte[] fileContent, List<int> positions)
        {
            string version = Utilities.GetFileVersion(fileContent);
            if (!string.IsNullOrWhiteSpace(version))
                return $"v{version}";

            return string.Empty;
        }
    }
}
