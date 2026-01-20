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
        public static IContentCheck[] ContentCheckClasses => [];

        // TODO: uncheck later
        /// <summary>
        /// Cache for all IDiskImageCheck<ISO9660> types
        /// </summary>
        public static IDiskImageCheck<ISO9660>[] ISO9660CheckClasses => [];

        /// <summary>
        /// Cache for all IExecutableCheck<LinearExecutable> types
        /// </summary>
        public static IExecutableCheck<LinearExecutable>[] LinearExecutableCheckClasses => [];

        /// <summary>
        /// Cache for all IExecutableCheck<MSDOS> types
        /// </summary>
        public static IExecutableCheck<MSDOS>[] MSDOSExecutableCheckClasses => [];

        /// <summary>
        /// Cache for all IExecutableCheck<NewExecutable> types
        /// </summary>
        public static IExecutableCheck<NewExecutable>[] NewExecutableCheckClasses => [];

        /// <summary>
        /// Cache for all IPathCheck types
        /// </summary>
        public static IPathCheck[] PathCheckClasses => [];

        /// <summary>
        /// Cache for all IExecutableCheck<PortableExecutable> types
        /// </summary>
        public static IExecutableCheck<PortableExecutable>[] PortableExecutableCheckClasses
        {
            get
            {
                portableExecutableCheckClasses ??=
                [
                    new Protection.SecuROM(),
                ];
                return portableExecutableCheckClasses;
            }
        }

        #endregion

        #region Internal Instances
        
        /// <summary>
        /// Cache for all IExecutableCheck<PortableExecutable> types
        /// </summary>
        private static IExecutableCheck<PortableExecutable>[]? portableExecutableCheckClasses;

        #endregion

        #region Helpers

        #endregion
    }
}
