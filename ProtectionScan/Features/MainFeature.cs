using System;
using System.Collections.Generic;
using System.IO;
using BinaryObjectScanner;
using SabreTools.CommandLine;
using SabreTools.CommandLine.Inputs;

namespace ProtectionScan.Features
{
    internal sealed class MainFeature : Feature
    {
        #region Feature Definition

        public const string DisplayName = "main";

        /// <remarks>Flags are unused</remarks>
        private static readonly string[] _flags = [];

        /// <remarks>Description is unused</remarks>
        private const string _description = "";

        #endregion

        #region Inputs

        private const string _debugName = "debug";
        internal readonly FlagInput DebugInput = new(_debugName, ["-d", "--debug"], "Enable debug mode");

        private const string _noArchivesName = "no-archives";
        internal readonly FlagInput NoArchivesInput = new(_noArchivesName, ["-na", "--no-archives"], "Disable scanning archives");

        private const string _noContentsName = "no-contents";
        internal readonly FlagInput NoContentsInput = new(_noContentsName, ["-nc", "--no-contents"], "Disable scanning for content checks");

        private const string _noPathsName = "no-paths";
        internal readonly FlagInput NoPathsInput = new(_noPathsName, ["-np", "--no-paths"], "Disable scanning for path checks");

        private const string _noSubdirsName = "no-subdirs";
        internal readonly FlagInput NoSubdirsInput = new(_noSubdirsName, ["-ns", "--no-subdirs"], "Disable scanning subdirectories");

        #endregion

        public MainFeature()
            : base(DisplayName, _flags, _description)
        {
            RequiresInputs = true;

            Add(DebugInput);
            Add(NoContentsInput);
            Add(NoArchivesInput);
            Add(NoPathsInput);
            Add(NoSubdirsInput);
        }

        /// <inheritdoc/>
        public override bool Execute()
        {
            // Create progress indicator
            var fileProgress = new Progress<ProtectionProgress>();
            fileProgress.ProgressChanged += Changed;

            // Create scanner for all paths
            var scanner = new Scanner(
                !GetBoolean(_noArchivesName),
                !GetBoolean(_noContentsName),
                !GetBoolean(_noPathsName),
                !GetBoolean(_noSubdirsName),
                GetBoolean(_debugName),
                fileProgress);

            // Loop through the input paths
            for (int i = 0; i < Inputs.Count; i++)
            {
                string arg = Inputs[i];
                GetAndWriteProtections(scanner, arg);
            }

            return true;
        }

        /// <inheritdoc/>
        public override bool VerifyInputs() => Inputs.Count > 0;

        /// <summary>
        /// Protection progress changed handler
        /// </summary>
        private static void Changed(object? source, ProtectionProgress value)
        {
            string prefix = string.Empty;
            for (int i = 0; i < value.Depth; i++)
            {
                prefix += "--> ";
            }

            Console.WriteLine($"{prefix}{value.Percentage * 100:N2}%: {value.Filename} - {value.Protection}");
        }

        /// <summary>
        /// Wrapper to get and log protections for a single path
        /// </summary>
        /// <param name="scanner">Scanner object to use</param>
        /// <param name="path">File or directory path</param>
        private static void GetAndWriteProtections(Scanner scanner, string path)
        {
            // Normalize by getting the full path
            path = Path.GetFullPath(path);

            // An invalid path can't be scanned
            if (!Directory.Exists(path) && !File.Exists(path))
            {
                Console.WriteLine($"{path} does not exist, skipping...");
                return;
            }

            try
            {
                var protections = scanner.GetProtections(path);
                WriteProtectionResultFile(path, protections);
            }
            catch (Exception ex)
            {
                try
                {
                    using var sw = new StreamWriter(File.OpenWrite($"exception-{DateTime.Now:yyyy-MM-dd_HHmmss.ffff}.txt"));
                    sw.WriteLine(ex);
                }
                catch
                {
                    Console.WriteLine("Could not open exception log file for writing. See original message below:");
                    Console.WriteLine(ex);
                }
            }
        }

        /// <summary>
        /// Write the protection results from a single path to file, if possible
        /// </summary>
        /// <param name="path">File or directory path</param>
        /// <param name="protections">Dictionary of protections found, if any</param>
        private static void WriteProtectionResultFile(string path, Dictionary<string, List<string>> protections)
        {
            if (protections == null)
            {
                Console.WriteLine($"No protections found for {path}");
                return;
            }

            // Attempt to open a protection file for writing
            StreamWriter? sw = null;
            try
            {
                sw = new StreamWriter(File.OpenWrite($"protection-{DateTime.Now:yyyy-MM-dd_HHmmss.ffff}.txt"));
            }
            catch
            {
                Console.WriteLine("Could not open protection log file for writing. Only a console log will be provided.");
            }

            // Sort the keys for consistent output
            string[] keys = [.. protections.Keys];
            Array.Sort(keys);

            // Loop over all keys
            foreach (string key in keys)
            {
                // Skip over files with no protection
                var value = protections[key];
                if (value.Count == 0)
                    continue;

                // Sort the detected protections for consistent output
                string[] fileProtections = [.. value];
                Array.Sort(fileProtections);

                // Format and output the line
                string line = $"{key}: {string.Join(", ", fileProtections)}";
                Console.WriteLine(line);
                sw?.WriteLine(line);
            }

            // Dispose of the writer
            sw?.Dispose();
        }
    }
}
