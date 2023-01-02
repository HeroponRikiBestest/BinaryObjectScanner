using System;
using System.Linq;
using BurnOutSharp.Models.Compression.Quantum;
using BurnOutSharp.Models.MicrosoftCabinet;

namespace BurnOutSharp.Compression.Quantum
{
    /// <see href="https://github.com/wine-mirror/wine/blob/master/dlls/cabinet/cabinet.h"/>
    /// <see href="https://github.com/wine-mirror/wine/blob/master/dlls/cabinet/fdi.c"/>
    /// <see href="https://github.com/wine-mirror/wine/blob/master/include/fdi.h"/>
    /// <see href="http://www.russotto.net/quantumcomp.html"/>
    public static class Decompressor
    {
        /// <summary>
        /// Decompress a data block using a given state
        /// </summary>
        public static byte[] Decompress(CFFOLDER folder, CFDATA dataBlock)
        {
            // If we have an invalid folder
            if (folder == null)
                return null;

            // If we have an invalid data block
            if (dataBlock?.CompressedData == null)
            {
                // Corrupt blocks will show as size 0
                int compressedSize = dataBlock?.CompressedSize ?? 0;
                if (compressedSize == 0)
                    compressedSize = 32768;

                return new byte[compressedSize];
            }

            // Setup the decompression state
            State state = new State();
            if (!InitState(state, folder))
                return new byte[dataBlock.UncompressedSize];

            // Setup the decompression variables
            int inlen = dataBlock.CompressedSize;
            byte[] inbuf = dataBlock.CompressedData;
            int outlen = dataBlock.UncompressedSize;
            byte[] outbuf = new byte[outlen];

            // Perform the decompression, if possible
            if (Decompress(state, inlen, inbuf, outlen, outbuf))
                return outbuf;
            else
                return new byte[outlen];
        }

        /// <summary>
        /// Decompress a byte array using a given State
        /// </summary>
        public static bool Decompress(State state, int inlen, byte[] inbuf, int outlen, byte[] outbuf)
        {
            int inpos = 0; // inbuf[0]
            int window = 0; // state.Window[0]
            int runsrc, rundest;
            uint window_posn = state.WindowPosition;
            uint window_size = state.WindowSize;

            int extra, togo = outlen, match_length = 0, copy_length;
            byte selector, sym;
            uint match_offset = 0;

            ushort H = 0xFFFF, L = 0;

            // Read initial value of C
            Q_INIT_BITSTREAM(out int bitsleft, out uint bitbuf);
            ushort C = Q_READ_BITS_UINT16(16, inbuf, ref inpos, ref bitsleft, ref bitbuf);

            // Apply 2^x-1 mask
            window_posn &= window_size - 1;

            // Runs can't straddle the window wraparound
            if ((window_posn + togo) > window_size)
                return false;

            while (togo > 0)
            {
                // If we have more requested bytes than we have data
                if (inpos >= inbuf.Length - 1)
                    break;

                selector = (byte)GET_SYMBOL(state.Model7, ref H, ref L, ref C, inbuf, ref inpos, ref bitsleft, ref bitbuf);
                switch (selector)
                {
                    // Selector 0 = literal model, 64 entries, 0x00-0x3F
                    case 0:
                        sym = (byte)GET_SYMBOL(state.Model7Submodel00, ref H, ref L, ref C, inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        state.Window[window + window_posn++] = sym;
                        togo--;
                        break;

                    // Selector 1 = literal model, 64 entries, 0x40-0x7F
                    case 1:
                        sym = (byte)GET_SYMBOL(state.Model7Submodel40, ref H, ref L, ref C, inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        state.Window[window + window_posn++] = sym;
                        togo--;
                        break;

                    // Selector 2 = literal model, 64 entries, 0x80-0xBF
                    case 2:
                        sym = (byte)GET_SYMBOL(state.Model7Submodel80, ref H, ref L, ref C, inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        state.Window[window + window_posn++] = sym;
                        togo--;
                        break;

                    // Selector 3 = literal model, 64 entries, 0xC0-0xFF
                    case 3:
                        sym = (byte)GET_SYMBOL(state.Model7SubmodelC0, ref H, ref L, ref C, inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        state.Window[window + window_posn++] = sym;
                        togo--;
                        break;

                    // Selector 4 = fixed length of 3
                    case 4:
                        sym = (byte)GET_SYMBOL(state.Model4, ref H, ref L, ref C, inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        extra = Q_READ_BITS_INT32(state.q_extra_bits[sym], inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        match_offset = (uint)(state.q_position_base[sym] + extra + 1);
                        match_length = 3;
                        break;

                    // Selector 5 = fixed length of 4
                    case 5:
                        sym = (byte)GET_SYMBOL(state.Model5, ref H, ref L, ref C, inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        extra = Q_READ_BITS_INT32(state.q_extra_bits[sym], inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        match_offset = (uint)(state.q_position_base[sym] + extra + 1);
                        match_length = 4;
                        break;

                    // Selector 6 = variable length
                    case 6:
                        sym = (byte)GET_SYMBOL(state.Model6Length, ref H, ref L, ref C, inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        extra = Q_READ_BITS_INT32(state.q_length_extra[sym], inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        match_length = state.q_length_base[sym] + extra + 5;
                        sym = (byte)GET_SYMBOL(state.Model6Position, ref H, ref L, ref C, inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        extra = Q_READ_BITS_INT32(state.q_extra_bits[sym], inbuf, ref inpos, ref bitsleft, ref bitbuf);
                        match_offset = (uint)(state.q_position_base[sym] + extra + 1);
                        break;

                    default:
                        return false;
                }

                // If this is a match
                if (selector >= 4)
                {
                    rundest = (int)(window + window_posn);
                    togo -= match_length;

                    // Copy any wrapped around source data
                    if (window_posn >= match_offset)
                    {
                        // No wrap
                        runsrc = (int)(rundest - match_offset);
                    }
                    else
                    {
                        runsrc = (int)(rundest + (window_size - match_offset));
                        copy_length = (int)(match_offset - window_posn);
                        if (copy_length < match_length)
                        {
                            match_length -= copy_length;
                            window_posn += (uint)copy_length;
                            while (copy_length-- > 0)
                            {
                                state.Window[rundest++] = state.Window[rundest++];
                            }

                            runsrc = window;
                        }
                    }

                    window_posn += (uint)match_length;

                    // Copy match data - no worries about destination wraps
                    while (match_length-- > 0)
                    {
                        state.Window[rundest++] = state.Window[runsrc++];
                    }
                }
            }

            if (togo != 0)
                return false;

            Array.Copy(state.Window, (window_posn == 0 ? window_size : window_posn) - outlen, outbuf, 0, outlen);

            state.WindowPosition = window_posn;
            return true;
        }

        /// <summary>
        /// Initialize a Quantum decompressor state
        /// </summary>
        public static bool InitState(State state, CFFOLDER folder)
        {
            int window = ((ushort)folder.CompressionType >> 8) & 0x1f;
            int level = ((ushort)folder.CompressionType >> 4) & 0xF;
            return InitState(state, window, level);
        }

        /// <summary>
        /// Initialize a Quantum decompressor state
        /// </summary>
        public static bool InitState(State state, int window, int level)
        {
            uint windowSize = (uint)(1 << window);
            int msz = window * 2, i;
            uint j;

            // QTM supports window sizes of 2^10 (1Kb) through 2^21 (2Mb)
            // If a previously allocated window is big enough, keep it
            if (window < 10 || window > 21)
                return false;

            // If we don't have the proper window size
            if (state.ActualSize < windowSize)
                state.Window = null;

            // If we have no window
            if (state.Window == null)
            {
                state.Window = new byte[windowSize];
                state.ActualSize = windowSize;
            }

            // Set the window size and position
            state.WindowSize = windowSize;
            state.WindowPosition = 0;

            // Initialize static slot/extrabits tables
            for (i = 0, j = 0; i < 27; i++)
            {
                state.q_length_extra[i] = (byte)((i == 26) ? 0 : (i < 2 ? 0 : i - 2) >> 2);
                state.q_length_base[i] = (byte)j; j += (uint)(1 << ((i == 26) ? 5 : state.q_length_extra[i]));
            }

            for (i = 0, j = 0; i < 42; i++)
            {
                state.q_extra_bits[i] = (byte)((i < 2 ? 0 : i - 2) >> 1);
                state.q_position_base[i] = j; j += (uint)(1 << state.q_extra_bits[i]);
            }

            // Initialize arithmetic coding models
            state.Model7 = CreateModel(state.Model7Symbols, 7, 0);

            state.Model7Submodel00 = CreateModel(state.Model7Submodel00Symbols, 0x40, 0x00);
            state.Model7Submodel40 = CreateModel(state.Model7Submodel40Symbols, 0x40, 0x40);
            state.Model7Submodel80 = CreateModel(state.Model7Submodel80Symbols, 0x40, 0x80);
            state.Model7SubmodelC0 = CreateModel(state.Model7SubmodelC0Symbols, 0x40, 0xC0);

            // Model 4 depends on table size, ranges from 20 to 24
            state.Model4 = CreateModel(state.Model4Symbols, (msz < 24) ? msz : 24, 0);

            // Model 5 depends on table size, ranges from 20 to 36
            state.Model5 = CreateModel(symbols: state.Model5Symbols, (msz < 36) ? msz : 36, 0);

            // Model 6 Position depends on table size, ranges from 20 to 42
            state.Model6Position = CreateModel(state.Model6PositionSymbols, msz, 0);
            state.Model6Length = CreateModel(state.Model6LengthSymbols, 27, 0);

            return true;
        }

        /// <summary>
        /// Initialize a Quantum model that decodes symbols from s to (s + n - 1)
        /// </summary>
        /// <see href="https://github.com/wine-mirror/wine/blob/master/dlls/cabinet/fdi.c"/>
        private static Model CreateModel(ModelSymbol[] symbols, int entryCount, int initialSymbol)
        {
            // Set the basic values
            Model model = new Model
            {
                TimeToReorder = 4,
                Entries = entryCount,
                Symbols = symbols,
            };

            // Clear out the look-up table
            model.LookupTable = Enumerable.Repeat<ushort>(0xFF, model.LookupTable.Length).ToArray();

            // Loop through and build the look-up table
            for (ushort i = 0; i < entryCount; i++)
            {
                // Set up a look-up entry for symbol
                model.LookupTable[i + initialSymbol] = i;

                // Create the symbol in the table
                model.Symbols[i] = new ModelSymbol
                {
                    Symbol = (ushort)(i + initialSymbol),
                    CumulativeFrequency = (ushort)(entryCount - i),
                };
            }

            // Set the last symbol frequency to 0
            model.Symbols[entryCount] = new ModelSymbol { CumulativeFrequency = 0 };
            return model;
        }

        /// <summary>
        /// Update the quantum model for a particular symbol
        /// </summary>
        /// <see href="https://github.com/wine-mirror/wine/blob/master/dlls/cabinet/fdi.c"/>
        private static void UpdateModel(Model model, int symbol)
        {
            // Update the cumulative frequency for all symbols less than the provided
            for (int i = 0; i < symbol; i++)
            {
                model.Symbols[i].CumulativeFrequency += 8;
            }

            // If the first symbol still has a cumulative frequency under 3800
            if (model.Symbols[0].CumulativeFrequency <= 3800)
                return;

            // If we have more than 1 shift left in the model
            if (--model.TimeToReorder != 0)
            {
                // Loop through the entries from highest to lowest,
                // performing the shift on the cumulative frequencies
                for (int i = model.Entries - 1; i >= 0; i--)
                {
                    // -1, not -2; the 0 entry saves this
                    model.Symbols[i].CumulativeFrequency >>= 1;
                    if (model.Symbols[i].CumulativeFrequency <= model.Symbols[i + 1].CumulativeFrequency)
                        model.Symbols[i].CumulativeFrequency = (ushort)(model.Symbols[i + 1].CumulativeFrequency + 1);
                }
            }

            // If we have no shifts left in the model
            else
            {
                // Reset the shifts left value to 50
                model.TimeToReorder = 50;

                // Loop through the entries setting the cumulative frequencies
                for (int i = 0; i < model.Entries; i++)
                {
                    // No -1, want to include the 0 entry
                    // This converts cumfreqs into frequencies, then shifts right
                    model.Symbols[i].CumulativeFrequency -= model.Symbols[i + 1].CumulativeFrequency;
                    model.Symbols[i].CumulativeFrequency++; // Avoid losing things entirely
                    model.Symbols[i].CumulativeFrequency >>= 1;
                }

                // Now sort by frequencies, decreasing order -- this must be an
                // inplace selection sort, or a sort with the same (in)stability
                // characteristics
                for (int i = 0; i < model.Entries - 1; i++)
                {
                    for (int j = i + 1; j < model.Entries; j++)
                    {
                        if (model.Symbols[i].CumulativeFrequency < model.Symbols[j].CumulativeFrequency)
                        {
                            var temp = model.Symbols[i];
                            model.Symbols[i] = model.Symbols[j];
                            model.Symbols[j] = temp;
                        }
                    }
                }

                // Then convert frequencies back to cumfreq
                for (int i = model.Entries - 1; i >= 0; i--)
                {
                    model.Symbols[i].CumulativeFrequency += model.Symbols[i + 1].CumulativeFrequency;
                }

                // Then update the other part of the table
                for (int i = 0; i < model.Entries; i++)
                {
                    model.LookupTable[model.Symbols[i].Symbol] = (ushort)i;
                }
            }
        }

        #region Macros

        /* Bitstream reading macros (Quantum / normal byte order)
            *
            * Q_INIT_BITSTREAM    should be used first to set up the system
            * Q_READ_BITS(var,n)  takes N bits from the buffer and puts them in var.
            *                     unlike LZX, this can loop several times to get the
            *                     requisite number of bits.
            * Q_FILL_BUFFER       adds more data to the bit buffer, if there is room
            *                     for another 16 bits.
            * Q_PEEK_BITS(n)      extracts (without removing) N bits from the bit
            *                     buffer
            * Q_REMOVE_BITS(n)    removes N bits from the bit buffer
            *
            * These bit access routines work by using the area beyond the MSB and the
            * LSB as a free source of zeroes. This avoids having to mask any bits.
            * So we have to know the bit width of the bitbuffer variable. This is
            * defined as Uint_BITS.
            *
            * Uint_BITS should be at least 16 bits. Unlike LZX's Huffman decoding,
            * Quantum's arithmetic decoding only needs 1 bit at a time, it doesn't
            * need an assured number. Retrieving larger bitstrings can be done with
            * multiple reads and fills of the bitbuffer. The code should work fine
            * for machines where Uint >= 32 bits.
            *
            * Also note that Quantum reads bytes in normal order; LZX is in
            * little-endian order.
            */

        // #define Q_INIT_BITSTREAM do { bitsleft = 0; bitbuf = 0; } while (0)

        // #define Q_FILL_BUFFER do {                                                  \
        // if (bitsleft <= (16)) {                                  \
        //     bitbuf |= ((inpos[0]<<8)|inpos[1]) << (32-16 - bitsleft);   \
        //     bitsleft += 16; inpos += 2;                                             \
        // }                                                                         \
        // } while (0)

        // #define Q_PEEK_BITS(n)   (bitbuf >> (32 - (n)))
        // #define Q_REMOVE_BITS(n) ((bitbuf <<= (n)), (bitsleft -= (n)))

        // #define Q_READ_BITS(v,n) do {                                           \
        // (v) = 0;                                                              \
        // for (bitsneed = (n); bitsneed; bitsneed -= bitrun) {                  \
        //     Q_FILL_BUFFER;                                                      \
        //     bitrun = (bitsneed > bitsleft) ? bitsleft : bitsneed;               \
        //     (v) = ((v) << bitrun) | Q_PEEK_BITS(bitrun);                        \
        //     Q_REMOVE_BITS(bitrun);                                              \
        // }                                                                     \
        // } while (0)

        // #define Q_MENTRIES(model) (state.qtm.model).Entries)
        // #define Q_MSYM(model,symidx) (state.qtm.model).syms[(symidx)].sym)
        // #define Q_MSYMFREQ(model,symidx) (state.qtm.model).syms[(symidx)].cumfreq)

        /* GET_SYMBOL(model, var) fetches the next symbol from the stated model
        * and puts it in var. it may need to read the bitstream to do this.
        */
        // #define GET_SYMBOL(m, var) do {                                         \
        // range =  ((H - L) & 0xFFFF) + 1;                                      \
        // symf = ((((C - L + 1) *  (state.qtm.m).syms[(0)].cumfreq) - 1) / range) & 0xFFFF;      \
        //                                                                         \
        // for (i=1; i < (state.qtm.m).Entries); i++) {                                   \
        //     if ((state.qtm.m).syms[(i)].cumfreq) <= symf) break;                                 \
        // }                                                                     \
        // (var) =  (state.qtm.m).syms[(i-1)].sym)                                   \
        //                                                                         \
        // range = (H - L) + 1;                                                  \
        // H = L + (((state.qtm.m).syms[(i-1)].cumfreq) * range) / (state.qtm.m).syms[(0)].cumfreq) - 1;          \
        // L = L + (((state.qtm.m).syms[(i)].cumfreq) * range) / (state.qtm.m).syms[(0)].cumfreq);              \
        // while (1) {                                                           \
        //     if ((L & 0x8000) != (H & 0x8000)) {                                 \
        //     if ((L & 0x4000) && !(H & 0x4000)) {                              \
        //         /* underflow case */                                            \
        //         C ^= 0x4000; L &= 0x3FFF; H |= 0x4000;                          \
        //     }                                                                 \
        //     else break;                                                       \
        //     }                                                                   \
        //     L <<= 1; H = (H << 1) | 1;                                          \
        //     Q_FILL_BUFFER;                                                      \
        //     C  = (C << 1) | Q_PEEK_BITS(1);                                     \
        //     Q_REMOVE_BITS(1);                                                   \
        // }                                                                     \
        //                                                                         \
        // Quantum.UpdateModel(&(state.qtm.m)), i);                                         \
        // } while (0)

        /// <summary>
        /// Should be used first to set up the system
        /// </summary>
        private static void Q_INIT_BITSTREAM(out int bitsleft, out uint bitbuf)
        {
            bitsleft = 0; bitbuf = 0;
        }

        /// <summary>
        /// Adds more data to the bit buffer, if there is room for another 16 bits.
        /// </summary>
        private static void Q_FILL_BUFFER(byte[] inbuf, ref int inpos, ref int bitsleft, ref uint bitbuf)
        {
            if (bitsleft <= 16)
            {
                bitbuf |= (uint)((inbuf[inpos + 0] << 8) | inbuf[inpos + 1]) << (16 - bitsleft);
                bitsleft += 16; inpos += 2;
            }
        }

        /// <summary>
        /// Extracts (without removing) N bits from the bit buffer
        /// </summary>
        private static uint Q_PEEK_BITS(int n, uint bitbuf)
        {
            return bitbuf >> (32 - n);
        }

        /// <summary>
        /// Removes N bits from the bit buffer
        /// </summary>
        private static void Q_REMOVE_BITS(int n, ref int bitsleft, ref uint bitbuf)
        {
            bitbuf <<= n;
            bitsleft -= n;
        }

        /// <summary>
        /// Takes N bits from the buffer and puts them in v. Unlike LZX, this can loop
        /// several times to get the requisite number of bits.
        /// </summary>
        private static ushort Q_READ_BITS_UINT16(int n, byte[] inbuf, ref int inpos, ref int bitsleft, ref uint bitbuf)
        {
            ushort v = 0; int bitrun;
            for (int bitsneed = n; bitsneed != 0; bitsneed -= bitrun)
            {
                Q_FILL_BUFFER(inbuf, ref inpos, ref bitsleft, ref bitbuf);

                bitrun = (bitsneed > bitsleft) ? bitsleft : bitsneed;
                v = (ushort)((v << bitrun) | Q_PEEK_BITS(bitrun, bitbuf));

                Q_REMOVE_BITS(bitrun, ref bitsleft, ref bitbuf);
            }

            return v;
        }

        /// <summary>
        /// Takes N bits from the buffer and puts them in v. Unlike LZX, this can loop
        /// several times to get the requisite number of bits.
        /// </summary>
        private static int Q_READ_BITS_INT32(int n, byte[] inbuf, ref int inpos, ref int bitsleft, ref uint bitbuf)
        {
            int v = 0; int bitrun;
            for (int bitsneed = n; bitsneed != 0; bitsneed -= bitrun)
            {
                Q_FILL_BUFFER(inbuf, ref inpos, ref bitsleft, ref bitbuf);

                bitrun = (bitsneed > bitsleft) ? bitsleft : bitsneed;
                v = (int)((v << bitrun) | Q_PEEK_BITS(bitrun, bitbuf));

                Q_REMOVE_BITS(bitrun, ref bitsleft, ref bitbuf);
            }

            return v;
        }

        /// <summary>
        /// Fetches the next symbol from the stated model and puts it in v.
        /// It may need to read the bitstream to do this.
        /// </summary>
        private static ushort GET_SYMBOL(Model model, ref ushort H, ref ushort L, ref ushort C, byte[] inbuf, ref int inpos, ref int bitsleft, ref uint bitbuf)
        {
            uint range = (uint)(((H - L) & 0xFFFF) + 1);
            ushort symf = (ushort)(((((C - L + 1) * model.Symbols[0].CumulativeFrequency) - 1) / range) & 0xFFFF);

            int i;
            for (i = 1; i < model.Entries; i++)
            {
                if (model.Symbols[i].CumulativeFrequency <= symf)
                    break;
            }

            ushort v = model.Symbols[i - 1].Symbol;
            range = (uint)(H - L + 1);
            H = (ushort)(L + ((model.Symbols[i - 1].CumulativeFrequency * range) / model.Symbols[0].CumulativeFrequency) - 1);
            L = (ushort)(L + ((model.Symbols[i].CumulativeFrequency * range) / model.Symbols[0].CumulativeFrequency));

            while (true)
            {
                if ((L & 0x8000) != (H & 0x8000))
                {
                    if ((L & 0x4000) != 0 && (H & 0x4000) == 0)
                    {
                        // Underflow case
                        C ^= 0x4000; L &= 0x3FFF; H |= 0x4000;
                    }
                    else
                    {
                        break;
                    }
                }

                L <<= 1; H = (ushort)((H << 1) | 1);

                // If we have more requested bytes than we have data
                if (inpos >= inbuf.Length - 1)
                    break;

                Q_FILL_BUFFER(inbuf, ref inpos, ref bitsleft, ref bitbuf);
                C = (ushort)((C << 1) | Q_PEEK_BITS(1, bitbuf));
                Q_REMOVE_BITS(1, ref bitsleft, ref bitbuf);
            }

            UpdateModel(model, i);
            return v;
        }

        #endregion
    }
}