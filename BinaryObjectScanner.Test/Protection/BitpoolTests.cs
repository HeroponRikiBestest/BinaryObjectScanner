﻿using System.Collections.Generic;
using BinaryObjectScanner.Protection;
using Xunit;

namespace BinaryObjectScanner.Test.Protection
{
    public class BitpoolTests
    {
        [Fact]
        public void CheckDirectoryPathTest()
        {
            string path = "path";
            List<string> files = [];

            var checker = new Bitpool();
            List<string> actual = checker.CheckDirectoryPath(path, files);
            Assert.Empty(actual);
        }

        [Fact]
        public void CheckFilePathTest()
        {
            string path = "path";

            var checker = new Bitpool();
            string? actual = checker.CheckFilePath(path);
            Assert.Null(actual);
        }
    }
}