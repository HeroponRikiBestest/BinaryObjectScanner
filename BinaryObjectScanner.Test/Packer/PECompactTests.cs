﻿using System.IO;
using BinaryObjectScanner.Packer;
using Xunit;

namespace BinaryObjectScanner.Test.Packer
{
    public class PECompactTests
    {
        [Fact]
        public void CheckPortableExecutableTest()
        {
            string file = "filename";
            SabreTools.Models.PortableExecutable.Executable model = new();
            Stream source = new MemoryStream();
            SabreTools.Serialization.Wrappers.PortableExecutable pex = new(model, source);

            var checker = new PECompact();
            string? actual = checker.CheckExecutable(file, pex, includeDebug: false);
            Assert.Null(actual);
        }
    
        [Fact]
        public void ExtractPortableExecutableTest()
        {
            string file = "filename";
            SabreTools.Models.PortableExecutable.Executable model = new();
            Stream source = new MemoryStream();
            SabreTools.Serialization.Wrappers.PortableExecutable pex = new(model, source);
            string outputDir = string.Empty;

            var checker = new PECompact();
            bool actual = checker.Extract(file, pex, outputDir, includeDebug: false);
            Assert.False(actual);
        }
    }
}