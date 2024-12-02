﻿using System.Collections.Generic;
using BinaryObjectScanner.Protection;
using Xunit;

namespace BinaryObjectScanner.Test.Protection
{
    public class DinamicMultimediaTests
    {
        [Fact]
        public void CheckDirectoryPathTest()
        {
            string path = "path";
            List<string> files = [];

            var checker = new DinamicMultimedia();
            List<string> actual = checker.CheckDirectoryPath(path, files);
            Assert.Empty(actual);
        }

        [Fact]
        public void CheckFilePathTest()
        {
            string path = "path";

            var checker = new DinamicMultimedia();
            string? actual = checker.CheckFilePath(path);
            Assert.Null(actual);
        }
    }
}