using System.IO;
using BinaryObjectScanner.GameEngine;
using Xunit;

namespace BinaryObjectScanner.Test.GameEngine
{
    public class RenderWareTests
    {
        [Fact]
        public void CheckPortableExecutableTest()
        {
            string file = "filename";
            SabreTools.Models.PortableExecutable.Executable model = new();
            Stream source = new MemoryStream();
            SabreTools.Serialization.Wrappers.PortableExecutable pex = new(model, source);

            var checker = new RenderWare();
            string? actual = checker.CheckExecutable(file, pex, includeDebug: false);
            Assert.Null(actual);
        }
    }
}