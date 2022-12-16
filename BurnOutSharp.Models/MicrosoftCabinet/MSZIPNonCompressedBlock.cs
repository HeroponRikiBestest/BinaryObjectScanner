namespace BurnOutSharp.Models.MicrosoftCabinet
{
    /// <summary>
    /// Non-compressed blocks (BTYPE=00)
    /// </summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc1951"/>
    public class MSZIPNonCompressedBlock : IMSZIPBlockData
    {
        /// <summary>
        /// The number of data bytes in the block
        /// </summary>
        /// <remarks>Bytes 0-1</remarks>
        public ushort LEN;

        /// <summary>
        /// The one's complement of LEN
        /// </summary>
        /// <remarks>Bytes 2-3</remarks>
        public ushort NLEN;

        /// <summary>
        /// <see cref="LEN"/> bytes of literal data
        /// </summary>
        public byte[] Data;
    }
}