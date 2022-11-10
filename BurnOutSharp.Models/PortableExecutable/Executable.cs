namespace BurnOutSharp.Models.PortableExecutable
{
    /// <summary>
    /// The following list describes the Microsoft PE executable format, with the
    /// base of the image header at the top. The section from the MS-DOS 2.0
    /// Compatible EXE Header through to the unused section just before the PE header
    /// is the MS-DOS 2.0 Section, and is used for MS-DOS compatibility only.
    /// </summary>
    /// <see href="https://learn.microsoft.com/en-us/windows/win32/debug/pe-format"/>
    public class Executable
    {
        /// <summary>
        /// MS-DOS executable stub
        /// </summary>
        public MSDOS.Executable Stub { get; set; }

        /// <summary>
        /// After the MS-DOS stub, at the file offset specified at offset 0x3c, is a 4-byte
        /// signature that identifies the file as a PE format image file. This signature is "PE\0\0"
        /// (the letters "P" and "E" followed by two null bytes).
        /// </summary>
        public byte[] Signature { get; set; }

        /// <summary>
        /// COFF file header
        /// </summary>
        public COFFFileHeader COFFFileHeader { get; set; }

        /// <summary>
        /// Optional header
        /// </summary>
        public OptionalHeader OptionalHeader { get; set; }

        // TODO: Support grouped sections in section reading and parsing
        // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#grouped-sections-object-only
        // Grouped sections are ordered and mean that the data in the sections contributes
        // to the "base" section (the one without the "$X" suffix). This may negatively impact
        // the use of some of the different types of executables.

        /// <summary>
        /// Section table
        /// </summary>
        public SectionHeader[] SectionTable { get; set; }

        /// <summary>
        /// COFF symbol table
        /// </summary>
        public COFFSymbolTableEntry[] COFFSymbolTable { get; set; }

        /// <summary>
        /// COFF string table
        /// </summary>
        public COFFStringTable COFFStringTable { get; set; }

        /// <summary>
        /// Attribute certificate table
        /// </summary>
        public AttributeCertificateTableEntry[] AttributeCertificateTable { get; set; }

        /// <summary>
        /// Delay-load directory table
        /// </summary>
        public DelayLoadDirectoryTable DelayLoadDirectoryTable { get; set; }

        #region Named Sections

        // .cormeta - CLR metadata is stored in this section. It is used to indicate that
        // the object file contains managed code. The format of the metadata is not
        // documented, but can be handed to the CLR interfaces for handling metadata.

        /// <summary>
        /// Export table (.edata)
        /// </summary>
        public ExportTable ExportTable { get; set; }

        /// <summary>
        /// Import table (.idata)
        /// </summary>
        public ImportTable ImportTable { get; set; }

        /// <summary>
        /// Resource directory table (.rsrc)
        /// </summary>
        public ResourceDirectoryTable ResourceDirectoryTable { get; set; }

        #endregion

        // TODO: Implement and/or document the following non-modeled parts:
        // - Delay Import Address Table
        // - Delay Import Name Table
        // - Delay Bound Import Address Table
        // - Delay Unload Import Address Table
        // - The .debug Section
        // - .debug$F (Object Only) / IMAGE_DEBUG_TYPE_FPO
        // - The .drectve Section (Object Only)
        // - The .pdata Section [Multiple formats per entry]
        // - TLS Callback Functions
        // - The .sxdata Section

        // TODO: Determine if "Archive (Library) File Format" is worth modelling
    }
}
