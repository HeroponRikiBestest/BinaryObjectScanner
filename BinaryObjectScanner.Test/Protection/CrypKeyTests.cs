﻿using System.Collections.Generic;
using System.IO;
using BinaryObjectScanner.Protection;
using Xunit;

namespace BinaryObjectScanner.Test.Protection
{
    public class CrypKeyTests
    {
        [Fact]
        public void CheckPortableExecutableTest()
        {
            string file = "filename";
            SabreTools.Data.Models.PortableExecutable.Executable model = new();
            Stream source = new MemoryStream(new byte[1024]);
            SabreTools.Serialization.Wrappers.PortableExecutable exe = new(model, source);

            var checker = new CrypKey();
            string? actual = checker.CheckExecutable(file, exe, includeDebug: false);
            Assert.Null(actual);
        }

        [Fact]
        public void CheckDirectoryPathTest()
        {
            string path = "path";
            List<string> files = [];

            var checker = new CrypKey();
            List<string> actual = checker.CheckDirectoryPath(path, files);
            Assert.Empty(actual);
        }

        [Fact]
        public void CheckFilePathTest()
        {
            string path = "path";

            var checker = new CrypKey();
            string? actual = checker.CheckFilePath(path);
            Assert.Null(actual);
        }
    }
}