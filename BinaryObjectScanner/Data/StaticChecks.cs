using System;
using System.Collections.Generic;
using System.Reflection;
using BinaryObjectScanner.Interfaces;
using SabreTools.Serialization.Wrappers;

namespace BinaryObjectScanner.Data
{
    internal static class StaticChecks
    {
        #region Public Collections

        /// <summary>
        /// Cache for all IContentCheck types
        /// </summary>
        public static IContentCheck[] ContentCheckClasses = [];
        
        /// <summary>
        /// Cache for all IDiskImageCheck<ISO9660> types
        /// </summary>
        public static IDiskImageCheck<ISO9660>[] ISO9660CheckClasses = [];

        /// <summary>
        /// Cache for all IExecutableCheck<LinearExecutable> types
        /// </summary>
        public static IExecutableCheck<LinearExecutable>[] LinearExecutableCheckClasses = [];

        /// <summary>
        /// Cache for all IExecutableCheck<MSDOS> types
        /// </summary>
        public static IExecutableCheck<MSDOS>[] MSDOSExecutableCheckClasses = [];

        /// <summary>
        /// Cache for all IExecutableCheck<NewExecutable> types
        /// </summary>
        public static IExecutableCheck<NewExecutable>[] NewExecutableCheckClasses = [];

        /// <summary>
        /// Cache for all IPathCheck types
        /// </summary>
        public static IPathCheck[] PathCheckClasses = [];

        /// <summary>
        /// Cache for all IExecutableCheck<PortableExecutable> types
        /// </summary>
        public static IExecutableCheck<PortableExecutable>[] PortableExecutableCheckClasses = [];

        #endregion

        #region Internal Instances

        #endregion

        #region Helpers

        /// <summary>
        /// Initialize all implementations of a type
        /// </summary>
        private static T[] InitCheckClasses<T>()
            => InitCheckClasses<T>(Assembly.GetExecutingAssembly());

        /// <summary>
        /// Initialize all implementations of a type
        /// </summary>
        private static T[] InitCheckClasses<T>(Assembly assembly)
        {
            // Get information from the type param
            string? interfaceName = typeof(T).FullName;
            if (interfaceName == null)
                return [];

            // If not all types can be loaded, use the ones that could be
            Type?[] assemblyTypes;
            try
            {
                assemblyTypes = assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException rtle)
            {
                assemblyTypes = rtle.Types ?? [];
            }

            // If no assembly types are found
            if (assemblyTypes.Length == 0)
                return [];

            // Loop through all types
            List<T> classTypes = [];
            foreach (Type? type in assemblyTypes)
            {
                // Skip invalid types
                if (type == null)
                    continue;

                // If the type isn't a class
                if (!type.IsClass)
                    continue;

                // If the type isn't a class or doesn't implement the interface
                var interfaces = Array.ConvertAll(type.GetInterfaces(), i => i.FullName);
                if (!Array.Exists(interfaces, i => i == interfaceName))
                    continue;

                // Try to create a concrete instance of the type
                var instance = (T?)Activator.CreateInstance(type);
                if (instance != null)
                    classTypes.Add(instance);
            }

            return [.. classTypes];
        }

        #endregion
    }
}
