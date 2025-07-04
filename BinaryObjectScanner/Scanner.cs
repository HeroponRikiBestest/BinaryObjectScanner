﻿using System;
using System.Collections.Generic;
using System.IO;
using BinaryObjectScanner.Data;
using BinaryObjectScanner.FileType;
using BinaryObjectScanner.Interfaces;
using SabreTools.IO.Extensions;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner
{
    public class Scanner
    {
        #region Options

        /// <summary>
        /// Options object for configuration
        /// </summary>
        private readonly Options _options;

        #endregion

        /// <summary>
        /// Optional progress callback during scanning
        /// </summary>
        private readonly IProgress<ProtectionProgress>? _fileProgress;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="scanArchives">Enable scanning archive contents</param>
        /// <param name="scanContents">Enable including content detections in output</param>
        /// <param name="scanPaths">Enable including path detections in output</param>
        /// <param name="scanSubdirectories">Enable scanning subdirectories</param>
        /// <param name="includeDebug">Enable including debug information</param>
        /// <param name="fileProgress">Optional progress callback</param>
        public Scanner(bool scanArchives,
            bool scanContents,
            bool scanPaths,
            bool scanSubdirectories,
            bool includeDebug,
            IProgress<ProtectionProgress>? fileProgress = null)
        {
            _options = new Options
            {
                ScanArchives = scanArchives,
                ScanContents = scanContents,
                ScanPaths = scanPaths,
                ScanSubdirectories = scanSubdirectories,
                IncludeDebug = includeDebug,
            };

            _fileProgress = fileProgress;

#if NET462_OR_GREATER || NETCOREAPP
            // Register the codepages
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
#endif
        }

        #region Scanning

        /// <summary>
        /// Scan a single path and get all found protections
        /// </summary>
        /// <param name="path">Path to scan</param>
        /// <returns>Dictionary of list of strings representing the found protections</returns>
        public ProtectionDictionary GetProtections(string path)
            => GetProtections([path]);

        /// <summary>
        /// Scan the list of paths and get all found protections
        /// </summary>
        /// <returns>Dictionary of list of strings representing the found protections</returns>
        public ProtectionDictionary GetProtections(List<string>? paths)
        {
            // If we have no paths, we can't scan
            if (paths == null || paths.Count == 0)
                return [];

            // Set a starting starting time for debug output
            DateTime startTime = DateTime.UtcNow;

            // Checkpoint
            _fileProgress?.Report(new ProtectionProgress(null, 0, null));

            // Temp variables for reporting
            string tempFilePath = Path.GetTempPath();
            string tempFilePathWithGuid = Path.Combine(tempFilePath, Guid.NewGuid().ToString());

            // Loop through each path and get the returned values
            var protections = new ProtectionDictionary();
            foreach (string path in paths)
            {
                // Directories scan each internal file individually
                if (Directory.Exists(path))
                {
                    // Enumerate all files at first for easier access
                    SearchOption searchOption = _options.ScanSubdirectories ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                    List<string> files = [.. IOExtensions.SafeGetFiles(path, "*", searchOption)];

                    // Scan for path-detectable protections
                    if (_options.ScanPaths)
                    {
                        var directoryPathProtections = HandlePathChecks(path, files);
                        protections.Append(directoryPathProtections);
                    }

                    // Scan each file in directory separately
                    for (int i = 0; i < files.Count; i++)
                    {
                        // Get the current file
                        string file = files[i];

                        // Get the reportable file name
                        string reportableFileName = file;
                        if (reportableFileName.StartsWith(tempFilePath))
                            reportableFileName = reportableFileName.Substring(tempFilePathWithGuid.Length);

                        // Checkpoint
                        _fileProgress?.Report(new ProtectionProgress(reportableFileName, i / (float)files.Count, "Checking file" + (file != reportableFileName ? " from archive" : string.Empty)));

                        // Scan for path-detectable protections
                        if (_options.ScanPaths)
                        {
                            var filePathProtections = HandlePathChecks(file, files: null);
                            if (filePathProtections != null && filePathProtections.Count > 0)
                                protections.Append(filePathProtections);
                        }

                        // Scan for content-detectable protections
                        var fileProtections = GetInternalProtections(file);
                        if (fileProtections != null && fileProtections.Count > 0)
                            protections.Append(fileProtections);

                        // Checkpoint
                        protections.TryGetValue(file, out var fullProtectionList);
                        var fullProtection = fullProtectionList != null && fullProtectionList.Count > 0
                            ? string.Join(", ", [.. fullProtectionList])
                            : null;
                        _fileProgress?.Report(new ProtectionProgress(reportableFileName, (i + 1) / (float)files.Count, fullProtection ?? string.Empty));
                    }
                }

                // Scan a single file by itself
                else if (File.Exists(path))
                {
                    // Get the reportable file name
                    string reportableFileName = path;
                    if (reportableFileName.StartsWith(tempFilePath))
                        reportableFileName = reportableFileName.Substring(tempFilePathWithGuid.Length);

                    // Checkpoint
                    _fileProgress?.Report(new ProtectionProgress(reportableFileName, 0, "Checking file" + (path != reportableFileName ? " from archive" : string.Empty)));

                    // Scan for path-detectable protections
                    if (_options.ScanPaths)
                    {
                        var filePathProtections = HandlePathChecks(path, files: null);
                        if (filePathProtections != null && filePathProtections.Count > 0)
                            protections.Append(filePathProtections);
                    }

                    // Scan for content-detectable protections
                    var fileProtections = GetInternalProtections(path);
                    if (fileProtections != null && fileProtections.Count > 0)
                        protections.Append(fileProtections);

                    // Checkpoint
                    protections.TryGetValue(path, out var fullProtectionList);
                    var fullProtection = fullProtectionList != null && fullProtectionList.Count > 0
                        ? string.Join(", ", [.. fullProtectionList])
                        : null;
                    _fileProgress?.Report(new ProtectionProgress(reportableFileName, 1, fullProtection ?? string.Empty));
                }

                // Throw on an invalid path
                else
                {
                    Console.WriteLine($"{path} is not a directory or file, skipping...");
                    //throw new FileNotFoundException($"{path} is not a directory or file, skipping...");
                }
            }

            // Clear out any empty keys
            protections.ClearEmptyKeys();

            // If we're in debug, output the elasped time to console
            if (_options.IncludeDebug)
                Console.WriteLine($"Time elapsed: {DateTime.UtcNow.Subtract(startTime)}");

            return protections;
        }

        /// <summary>
        /// Get the content-detectable protections associated with a single path
        /// </summary>
        /// <param name="file">Path to the file to scan</param>
        /// <returns>Dictionary of list of strings representing the found protections</returns>
        private ProtectionDictionary GetInternalProtections(string file)
        {
            // Quick sanity check before continuing
            if (!File.Exists(file))
                return [];

            // Open the file and begin scanning
            try
            {
                using FileStream fs = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                return GetInternalProtections(fs.Name, fs);
            }
            catch (Exception ex)
            {
                if (_options.IncludeDebug) Console.WriteLine(ex);

                var protections = new ProtectionDictionary();
                protections.Append(file, _options.IncludeDebug ? ex.ToString() : "[Exception opening file, please try again]");
                protections.ClearEmptyKeys();
                return protections;
            }
        }

        /// <summary>
        /// Get the content-detectable protections associated with a single path
        /// </summary>
        /// <param name="fileName">Name of the source file of the stream, for tracking</param>
        /// <param name="stream">Stream to scan the contents of</param>
        /// <returns>Dictionary of list of strings representing the found protections</returns>
        private ProtectionDictionary GetInternalProtections(string fileName, Stream stream)
        {
            // Quick sanity check before continuing
            if (!stream.CanRead)
                return [];

            // Initialize the protections found
            var protections = new ProtectionDictionary();

            // Get the extension for certain checks
            string extension = Path.GetExtension(fileName).ToLower().TrimStart('.');

            // Open the file and begin scanning
            try
            {
                // Get the first 16 bytes for matching
                byte[] magic = new byte[16];
                try
                {
                    int read = stream.Read(magic, 0, 16);
                    stream.Seek(0, SeekOrigin.Begin);
                }
                catch (Exception ex)
                {
                    if (_options.IncludeDebug) Console.WriteLine(ex);

                    return [];
                }

                // Get the file type either from magic number or extension
                WrapperType fileType = WrapperFactory.GetFileType(magic, extension);
                if (fileType == WrapperType.UNKNOWN)
                    return [];

                #region Non-Archive File Types

                // Create a detectable for the given file type
                var detectable = Factory.CreateDetectable(fileType);

                // If we're scanning file contents
                if (detectable != null && _options.ScanContents)
                {
                    // If we have an executable, it needs to bypass normal handling
                    if (detectable is Executable executable)
                    {
                        var subProtections = executable.DetectDict(stream, fileName, GetProtections, _options.IncludeDebug);
                        protections.Append(subProtections);
                    }

                    // Otherwise, use the default implementation
                    else
                    {
                        var subProtection = detectable.Detect(stream, fileName, _options.IncludeDebug);
                        protections.Append(fileName, subProtection);
                    }
                }

                #endregion

                #region Archive File Types

                // Create an extractable for the given file type
                var extractable = Factory.CreateExtractable(fileType);

                // If we're scanning archives
                if (extractable != null && _options.ScanArchives)
                {
                    // If the extractable file itself fails
                    try
                    {
                        // Extract and get the output path
                        string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
                        bool extracted = extractable.Extract(stream, fileName, tempPath, _options.IncludeDebug);

                        // Collect and format all found protections
                        ProtectionDictionary? subProtections = null;
                        if (extracted)
                            subProtections = GetProtections(tempPath);

                        // If temp directory cleanup fails
                        try
                        {
                            if (Directory.Exists(tempPath))
                                Directory.Delete(tempPath, true);
                        }
                        catch (Exception ex)
                        {
                            if (_options.IncludeDebug) Console.WriteLine(ex);
                        }

                        // Prepare the returned protections
                        subProtections?.StripFromKeys(tempPath);
                        subProtections?.PrependToKeys(fileName);
                        if (subProtections != null)
                            protections.Append(subProtections);
                    }
                    catch (Exception ex)
                    {
                        if (_options.IncludeDebug) Console.WriteLine(ex);
                    }
                }

                #endregion
            }
            catch (Exception ex)
            {
                if (_options.IncludeDebug) Console.WriteLine(ex);
                protections.Append(fileName, _options.IncludeDebug ? ex.ToString() : "[Exception opening file, please try again]");
            }

            // Clear out any empty keys
            protections.ClearEmptyKeys();

            return protections;
        }

        #endregion

        #region Path Handling

        /// <summary>
        /// Handle a single path based on all path check implementations
        /// </summary>
        /// <param name="path">Path of the file or directory to check</param>
        /// <param name="scanner">Scanner object to use for options and scanning</param>
        /// <returns>Set of protections in file, null on error</returns>
        private static ProtectionDictionary HandlePathChecks(string path, List<string>? files)
        {
            // Create the output dictionary
            var protections = new ProtectionDictionary();

            // Preprocess the list of files
            files = files?
                .ConvertAll(f => f.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar));

            // Iterate through all checks
            StaticChecks.PathCheckClasses.IterateWithAction(checkClass =>
            {
                var subProtections = PerformPathCheck(checkClass, path, files);
                protections.Append(path, subProtections);
            });

            return protections;
        }

        /// <summary>
        /// Handle files based on an IPathCheck implementation
        /// </summary>
        /// <param name="impl">IPathCheck class representing the file type</param>
        /// <param name="path">Path of the file or directory to check</param>
        /// <returns>Set of protections in path, empty on error</returns>
        private static List<string> PerformPathCheck(IPathCheck impl, string? path, List<string>? files)
        {
            // If we have an invalid path
            if (string.IsNullOrEmpty(path))
                return [];

            // Setup the list
            var protections = new List<string>();

            // If we have a file path
            if (File.Exists(path))
            {
                var protection = impl.CheckFilePath(path!);
                if (protection != null)
                    protections.Add(protection);
            }

            // If we have a directory path
            if (Directory.Exists(path) && files != null && files.Count > 0)
            {
                var subProtections = impl.CheckDirectoryPath(path!, files);
                if (subProtections != null)
                    protections.AddRange(subProtections);
            }

            return protections;
        }

        #endregion
    }
}
