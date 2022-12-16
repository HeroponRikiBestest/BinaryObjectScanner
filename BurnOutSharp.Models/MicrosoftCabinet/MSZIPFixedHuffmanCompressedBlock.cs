using System;

namespace BurnOutSharp.Models.MicrosoftCabinet
{
    /// <summary>
    /// Compression with fixed Huffman codes (BTYPE=01)
    /// </summary>
    /// <see href="https://interoperability.blob.core.windows.net/files/MS-MCI/%5bMS-MCI%5d.pdf"/>
    /// <see href="https://www.rfc-editor.org/rfc/rfc1951"/>
    public class MSZIPFixedHuffmanCompressedBlock : MSZIPCompressedBlock
    {
        #region Properties

        /// <inheritdoc/>
        public override int[] LiteralLengths
        {
            get
            {
                // If we have cached lengths, use those
                if (_literalLengths != null)
                    return _literalLengths;

                // Otherwise, build it from scratch
                _literalLengths = new int[288];

                // Literal Value 0 - 143, 8 bits
                for (int i = 0; i < 144; i++)
                    _literalLengths[i] = 8;

                // Literal Value 144 - 255, 9 bits
                for (int i = 144; i < 256; i++)
                    _literalLengths[i] = 9;

                // Literal Value 256 - 279, 7 bits
                for (int i = 256; i < 280; i++)
                    _literalLengths[i] = 7;

                // Literal Value 280 - 287, 8 bits
                for (int i = 280; i < 288; i++)
                    _literalLengths[i] = 8;

                return _literalLengths;
            }
            set
            {
                throw new FieldAccessException();
            }
        }

        /// <inheritdoc/>
        public override int[] DistanceCodes
        {
            get
            {
                // If we have cached distances, use those
                if (_distanceCodes != null)
                    return _distanceCodes;

                // Otherwise, build it from scratch
                _distanceCodes = new int[32];

                // Fixed length, 5 bits
                for (int i = 0; i < 32; i++)
                    _distanceCodes[i] = 5;

                return _distanceCodes;
            }
            set
            {
                throw new FieldAccessException();
            }
        }

        #endregion

        #region Instance Variables

        /// <summary>
        /// Huffman code lengths for the literal / length alphabet
        /// </summary>
        private int[] _literalLengths = null;

        /// <summary>
        /// Huffman distance codes for the literal / length alphabet
        /// </summary>
        private int[] _distanceCodes = null;

        #endregion
    }
}