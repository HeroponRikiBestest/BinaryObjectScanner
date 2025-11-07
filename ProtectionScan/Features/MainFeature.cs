using System;
using System.Collections.Generic;
using System.IO;
#if NETCOREAPP
using System.Linq;
#endif
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

        private const string _jsonName = "json";
        internal readonly FlagInput JsonInput = new(_jsonName, ["-j", "--json"], "Output to json file");

        private const string _nestedName = "nested";
        internal readonly FlagInput NestedInput = new(_nestedName, ["-n", "--nested"], "If outputting to json file, enable nested output");
        
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
            Add(JsonInput);
            Add(NestedInput);
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
                GetAndWriteProtections(scanner, arg, GetBoolean(_jsonName), GetBoolean(_nestedName));
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
        private static void GetAndWriteProtections(Scanner scanner, string path, bool json, bool nested)
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
#if NETCOREAPP
                
                if (json)
                    if (nested)
                        WriteProtectionResultNestedJson(path, protections);
                    else
                        WriteProtectionResultJson(path, protections);
                else
                    WriteProtectionResultFile(path, protections);
#else
                WriteProtectionResultFile(path, protections);
#endif
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
        
#if NETCOREAPP
        /// <summary>
        /// Write the protection results from a single path to a json file, if possible
        /// </summary>
        /// <param name="path">File or directory path</param>
        /// <param name="protections">Dictionary of protections found, if any</param>
        private static void WriteProtectionResultJson(string path, Dictionary<string, List<string>> protections)
        {
            if (protections == null)
            {
                Console.WriteLine($"No protections found for {path}");
                return;
            }

            // Attempt to open a protection file for writing
            StreamWriter? jsw = null;
            try
            {
                jsw = new StreamWriter(File.OpenWrite($"protection-{DateTime.Now:yyyy-MM-dd_HHmmss.ffff}.json"));
            }
            catch
            {
                Console.WriteLine("Could not open protection log file for writing. Only a console log will be provided.");
            }
            
            // Create the output data
            string serializedData = System.Text.Json.JsonSerializer.Serialize(protections, JsonSerializerOptions);

            // Write the output data
            // TODO: this prints plus symbols wrong, probably some other things too
            jsw?.WriteLine(serializedData);
            jsw?.Flush();
            
            // Dispose of the writer
            jsw?.Dispose();
        }
        
        /// <summary>
        /// Write the protection results from a single path to a json file, if possible
        /// </summary>
        /// <param name="path">File or directory path</param>
        /// <param name="protections">Dictionary of protections found, if any</param>
        private static void WriteProtectionResultNestedJson(string path, Dictionary<string, List<string>> protections)
        {
            if (protections == null)
            {
                Console.WriteLine($"No protections found for {path}");
                return;
            }

            // Attempt to open a protection file for writing
            StreamWriter? jsw = null;
            try
            {
                jsw = new StreamWriter(File.OpenWrite($"protection-{DateTime.Now:yyyy-MM-dd_HHmmss.ffff}.json"));
            }
            catch
            {
                Console.WriteLine("Could not open protection log file for writing. Only a console log will be provided.");
            }

            if (Directory.Exists(path))
            {
                // Sort the keys for consistent output
                string[] keys = [.. protections.Keys];
                Array.Sort(keys);
            
                // Remove starting path
                int pathLength = path.Length + 1;
                string cleanedPath = path;
                char pathChar = Path.DirectorySeparatorChar;

                if (pathChar == '\\' && path.EndsWith('\\'))
                {
                    pathLength -= 1;
                    cleanedPath = path.Substring(0, pathLength - 1);         
                }
                else if (pathChar == '/' && path.EndsWith('/'))
                {
                    pathLength -= 1;
                    cleanedPath = path.Substring(0, pathLength - 1);         
                }
                
                Dictionary<string, dynamic> rootDictionary = new Dictionary<string, dynamic>();
                Stack<Dictionary<string, dynamic>> dictionaryStack = new Stack<Dictionary<string, dynamic>>();
                Dictionary<string, string[]>? workingDirectoryProtections = null; //new Dictionary<string, dynamic>();
                string workingDirectoryString = "";

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

                    string filterKey;
                    if (key.Length < pathLength)
                        filterKey = "";
                    else
                        filterKey = key.Substring(pathLength);
                    
                    if (filterKey == pathChar.ToString())
                        filterKey = "";
                    
                    int index = filterKey.LastIndexOf(pathChar);
                    string currentDirectoryString = "";
                    if (index >= 0)
                        currentDirectoryString = filterKey.Substring(0, filterKey.LastIndexOf(pathChar));

                    while (workingDirectoryString != currentDirectoryString)
                    {
                        if (workingDirectoryProtections != null)
                        {
                            string directoryName;
                            int directoryNameIndex = workingDirectoryString.LastIndexOf(pathChar);
                            if (directoryNameIndex < 0)
                                directoryName = workingDirectoryString;
                            else
                                directoryName = workingDirectoryString.Substring(0, directoryNameIndex);

                            if (dictionaryStack.Count == 0)
                                rootDictionary.Add(directoryName, workingDirectoryProtections);
                            else
                            {
                                var tempDictionary = new Dictionary<string, dynamic>()
                                {
                                    {directoryName, workingDirectoryProtections},
                                };
                                
                                dictionaryStack.Push(tempDictionary);
                            }
                            workingDirectoryProtections = null;
                        }

                        if (currentDirectoryString.StartsWith(workingDirectoryString)) // FORWARD
                        {
                            int nextDirectoryIndex = currentDirectoryString.IndexOf(pathChar, workingDirectoryString.Length + 1);
                            if (nextDirectoryIndex < 0)
                                nextDirectoryIndex = currentDirectoryString.IndexOf(pathChar, workingDirectoryString.Length);

                            string nextDirectory = currentDirectoryString.Substring(0, nextDirectoryIndex);
                            var tempDictionary = new Dictionary<string, dynamic>()
                            {
                                {nextDirectory, new Dictionary<string, dynamic>()},
                            };
                            dictionaryStack.Push(tempDictionary);
                            if (workingDirectoryString == "")
                                workingDirectoryString = nextDirectory;
                            else
                                workingDirectoryString = workingDirectoryString + pathChar + nextDirectory;
                        }
                        else // BACKWARD
                        {
                            int nextDirectoryIndex = workingDirectoryString.LastIndexOf(pathChar);
                            string nextDirectory = workingDirectoryString.Substring(nextDirectoryIndex + 1);
                            if (dictionaryStack.Count <= 0)
                            {
                                Console.WriteLine($"Everything has gone wrong");
                            } 
                            else if (dictionaryStack.Count == 1)
                            {
                                var tempDictionary = dictionaryStack.Pop();
                                rootDictionary.Add(nextDirectory, tempDictionary);
                            }
                            else
                            {
                                var fartherFromRootDictionary = dictionaryStack.Pop();
                                var closerToRootDictionary = dictionaryStack.Pop();
                                closerToRootDictionary.Add(nextDirectory, fartherFromRootDictionary);
                                dictionaryStack.Push(closerToRootDictionary);
                            }
                            workingDirectoryString = workingDirectoryString.Substring(0, nextDirectoryIndex);
                        }
                    }
                    
                    if (workingDirectoryProtections == null)
                        workingDirectoryProtections = new Dictionary<string, string[]>();
                    
                    if (index < 0)
                        workingDirectoryProtections.Add(filterKey, fileProtections);
                    else
                        workingDirectoryProtections.Add(filterKey.Substring(index + 1), fileProtections);
                }
                if (workingDirectoryProtections != null)
                {
                    string directoryName;
                    int directoryNameIndex = workingDirectoryString.LastIndexOf(pathChar);
                    if (directoryNameIndex < 0)
                        directoryName = workingDirectoryString;
                    else
                        directoryName = workingDirectoryString.Substring(0, directoryNameIndex);

                    if (dictionaryStack.Count == 0)
                        rootDictionary.Add(directoryName, workingDirectoryProtections);
                    else
                    {
                        var tempDictionary = dictionaryStack.Pop();
                        if (!tempDictionary.ContainsKey(directoryName))
                        {
                            tempDictionary.Add(directoryName, workingDirectoryProtections);// this should never happen
                            Console.WriteLine($"This should never happen");
                        }
                        else
                        {
                            tempDictionary[directoryName] = workingDirectoryProtections;// this should never happen
                        }
                                
                        dictionaryStack.Push(tempDictionary);
                    }
                    workingDirectoryProtections = null;
                }

                while (dictionaryStack.Count >= 1)
                {
                    int nextDirectoryIndex = workingDirectoryString.LastIndexOf(pathChar);
                    string nextDirectory = workingDirectoryString.Substring(nextDirectoryIndex + 1);
                    if (dictionaryStack.Count <= 0)
                    {
                        Console.WriteLine($"Everything has gone wrong");
                    } 
                    else if (dictionaryStack.Count == 1)
                    {
                        var tempDictionary = dictionaryStack.Pop();
                        var directoryKey = tempDictionary.Keys.First();
                        rootDictionary.Add(nextDirectory, tempDictionary[directoryKey]);
                    }
                    else
                    {
                        var fartherFromRootDictionary = dictionaryStack.Pop();
                        var closerToRootDictionary = dictionaryStack.Pop();
                        
                        var closerDirectoryKey = closerToRootDictionary.Keys.First();
                        var fartherDirectoryKey = fartherFromRootDictionary.Keys.First();
                        closerToRootDictionary[closerDirectoryKey].Add(nextDirectory, fartherFromRootDictionary[fartherDirectoryKey]);
                        dictionaryStack.Push(closerToRootDictionary);
                    }
                } // Should end with WDS = ""

                Dictionary<string, dynamic> finalDictionary = new Dictionary<string, dynamic>()
                {
                    {cleanedPath, rootDictionary}
                };
                
                // Create the output data
                string serializedData = System.Text.Json.JsonSerializer.Serialize(finalDictionary, JsonSerializerOptions);

                // Write the output data
                // TODO: this prints plus symbols wrong, probably some other things too
                if (jsw != null)
                {
                    jsw.WriteLine(serializedData);
                    jsw.Flush();

                    // Dispose of the writer
                    jsw.Dispose();
                }
                else
                {
                    Console.WriteLine($"Null writer error");
                }
            }
            else
            {
                // Create the output data
                string serializedData = System.Text.Json.JsonSerializer.Serialize(protections, JsonSerializerOptions);

                // Write the output data
                // TODO: this prints plus symbols wrong, probably some other things too
                jsw?.WriteLine(serializedData);
                jsw?.Flush();
            
                // Dispose of the writer
                jsw?.Dispose();
            }
        }
        
        /// <summary>
        /// JSON serializer options for output printing
        /// </summary>
        private static System.Text.Json.JsonSerializerOptions JsonSerializerOptions
        {
            get
            {
#if NETCOREAPP3_1
                var serializer = new System.Text.Json.JsonSerializerOptions { WriteIndented = true };
#else
                var serializer = new System.Text.Json.JsonSerializerOptions { IncludeFields = true, WriteIndented = true };
#endif
                return serializer;
            }
        }
#endif
    }
}
