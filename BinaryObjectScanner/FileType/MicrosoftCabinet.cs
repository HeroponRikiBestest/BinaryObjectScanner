using System.IO;
using SabreTools.Data.Models.MicrosoftCabinet;

namespace BinaryObjectScanner.FileType
{
    /// <summary>
    /// Microsoft Cabinet
    /// </summary>
    public class MicrosoftCabinet : DetectableBase<SabreTools.Serialization.Wrappers.MicrosoftCabinet>
    {
        /// <inheritdoc/>
        public MicrosoftCabinet(SabreTools.Serialization.Wrappers.MicrosoftCabinet wrapper) : base(wrapper) { }

        /// <inheritdoc/>
        public override string? Detect(Stream stream, string file, bool includeDebug)
            => $"Microsoft Cabinet - {GetCompression()}";
        
        public string GetCompression()
        {
            if (_wrapper.Folders != null)
            {
                var folder = _wrapper.Folders[0];
                if ((folder!.CompressionType & CompressionType.MASK_TYPE) == CompressionType.TYPE_NONE)
                    return "Uncompressed";
                else if ((folder.CompressionType & CompressionType.MASK_TYPE) == CompressionType.TYPE_MSZIP)
                    return "MSZIP";
                else if ((folder.CompressionType & CompressionType.MASK_TYPE) == CompressionType.TYPE_QUANTUM)
                    return "Quantum";
                else if ((folder.CompressionType & CompressionType.MASK_TYPE) == CompressionType.TYPE_LZX)
                    return "LZX";
                else
                    return "Unknown";
            }
            return "Unknown";
        }
    }
}