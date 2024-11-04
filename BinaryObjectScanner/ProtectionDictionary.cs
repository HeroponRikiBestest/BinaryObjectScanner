using System;
#if NET40_OR_GREATER || NETCOREAPP
using System.Collections.Concurrent;
#endif
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace BinaryObjectScanner
{
    /// <summary>
    /// Represents a mapping from file to a set of protections
    /// </summary>
#if NET20 || NET35
    public class ProtectionDictionary : Dictionary<string, Queue<string>>
#else
    public class ProtectionDictionary : ConcurrentDictionary<string, ConcurrentQueue<string>>
#endif
    {
        /// <summary>
        /// Append one result to a results dictionary
        /// </summary>
        /// <param name="key">Key to add information to</param>
        /// <param name="value">String value to add</param>
        public void Append(string key, string value)
        {
            // If the value is empty, don't add it
            if (string.IsNullOrEmpty(value))
                return;

            Append(key, [value]);
        }

        /// <summary>
        /// Append one set of results to a results dictionary
        /// </summary>
        /// <param name="key">Key to add information to</param>
        /// <param name="values">String value array to add</param>
        public void Append(string key, string[] values)
        {
            // Use a placeholder value if the key is null
            key ??= "NO FILENAME";

            // Add the key if needed and then append the lists
            EnsureKey(key);
            AddRangeToKey(key, values);
        }

        /// <summary>
        /// Append one set of results to a results dictionary
        /// </summary>
        /// <param name="key">Key to add information to</param>
        /// <param name="value">String value to add</param>
        public void Append(string key, IEnumerable<string> values)
        {
            // Use a placeholder value if the key is null
            key ??= "NO FILENAME";

            // Add the key if needed and then append the lists
            EnsureKey(key);
            AddRangeToKey(key, values);
        }

        /// <summary>
        /// Append one results dictionary to another
        /// </summary>
        /// <param name="addition">Dictionary to pull from</param>
        public void Append(ProtectionDictionary? addition)
        {
            // If the dictionary is missing, just return
            if (addition == null)
                return;

            // Loop through each of the addition keys and add accordingly
            foreach (string key in addition.Keys)
            {
                EnsureKey(key);
                AddRangeToKey(key, addition[key]);
            }
        }

        /// <summary>
        /// Remove empty or null keys from a results dictionary
        /// </summary>
        public void ClearEmptyKeys()
        {
            // Get a list of all of the keys
            var keys = Keys.ToList();

            // Iterate and reset keys
            for (int i = 0; i < keys.Count; i++)
            {
                // Get the current key
                string key = keys[i];

                // If the key is empty, remove it
                if (this[key] == null || !this[key].Any())
#if NET20 || NET35
                    Remove(key);
#else
                    TryRemove(key, out _);
#endif
            }
        }

        /// <summary>
        /// Prepend a parent path from dictionary keys, if possible
        /// </summary>
        /// <param name="pathToPrepend">Path to strip from the keys</param>
        public void PrependToKeys(string pathToPrepend)
        {
            // Use a placeholder value if the path is null
            pathToPrepend = (pathToPrepend ?? "ARCHIVE").TrimEnd(Path.DirectorySeparatorChar);

            // Get a list of all of the keys
            var keys = Keys.ToList();

            // Iterate and reset keys
            for (int i = 0; i < keys.Count; i++)
            {
                // Get the current key
                string currentKey = keys[i];

                // Otherwise, get the new key name and transfer over
                string newKey = $"{pathToPrepend}{Path.DirectorySeparatorChar}{currentKey.Trim(Path.DirectorySeparatorChar)}";
                this[newKey] = this[currentKey];
#if NET20 || NET35
                Remove(currentKey);
#else
                TryRemove(currentKey, out _);
#endif
            }
        }

        /// <summary>
        /// Strip a parent path from dictionary keys, if possible
        /// </summary>
        /// <param name="pathToStrip">Path to strip from the keys</param>
        public void StripFromKeys(string? pathToStrip)
        {
            // If the path is missing, we can't do anything
            if (string.IsNullOrEmpty(pathToStrip))
                return;

            // Get a list of all of the keys
            var keys = Keys.ToList();

            // Iterate and reset keys
            for (int i = 0; i < keys.Count; i++)
            {
                // Get the current key
                string currentKey = keys[i];

                // If the key doesn't start with the path, don't touch it
                if (!currentKey.StartsWith(pathToStrip, StringComparison.OrdinalIgnoreCase))
                    continue;

                // Otherwise, get the new key name and transfer over
                string newKey = currentKey.Substring(pathToStrip!.Length);
                this[newKey] = this[currentKey];
#if NET20 || NET35
                Remove(currentKey);
#else
                TryRemove(currentKey, out _);
#endif
            }
        }

        /// <summary>
        /// Add a range of values from one queue to another
        /// </summary>
        /// <param name="original">Queue to add data to</param>
        /// <param name="values">Queue to get data from</param>
        private void AddRangeToKey(string key, IEnumerable<string> values)
        {
            if (values == null || !values.Any())
                return;

            foreach (string value in values)
            {
                this[key].Enqueue(value);
            }
        }

        /// <summary>
        /// Ensure the collection for the given key exists
        /// </summary>
        private void EnsureKey(string key)
        {
#if NET20 || NET35
            if (!ContainsKey(key))
                this[key] = new Queue<string>();
#else
            TryAdd(key, new ConcurrentQueue<string>());
#endif
        }
    }
}