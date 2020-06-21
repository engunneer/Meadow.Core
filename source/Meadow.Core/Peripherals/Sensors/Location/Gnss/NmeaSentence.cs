﻿using System;
using System.Collections.Generic;
using Meadow.Utilities;

namespace Meadow.Peripherals.Sensors.Location.Gnss
{
    /// <summary>
    /// Represents a NMEA data sentence typically used in GPS/GNSS systems. 
    /// </summary>
    /// <remarks>
    /// For additional info on NMEA sentences, an excellent reference 
    /// can found [here](https://gpsd.gitlab.io/gpsd/NMEA.html).
    /// </remarks>
    public class NmeaSentence
    {
        /// <summary>
        /// The prefix, including the `$` symbol of the sentence, i.e.: `$GPRMC`.
        /// </summary>
        public string Prefix { get; set; }

        /// <summary>
        /// A list of strings that represent the data elements within a NMEA
        /// sentence, between the prefix and the checksum data. 
        /// </summary>
        public List<string> DataElements { get; set; } = new List<string>();

        /// <summary>
        /// The checksum data of the data elements. Calculated by `XOR`ing
        /// all of the data elements.
        /// </summary>
        public byte Checksum {
            get { return ChecksumCalculator.XOR(GetDataString()); }
        }

        /// <summary>
        /// Returns the NMEA sentence string without the checksum digits.
        /// </summary>
        /// <returns></returns>
        protected string GetDataString()
        {
            return $"{Prefix},{String.Join(",", DataElements)}";
        }

        /// <summary>
        /// Returns a fully-expressed NMEA data string, including the prefix,
        /// data elements, and checksum information.
        ///
        /// I.e.: $GPRMC,000049.799,V,,,,,0.00,0.00,060180,,,N*48
        /// </summary>
        /// <returns>A string of the sentence.</returns>
        public override string ToString()
        {
            string data = GetDataString(); //don't want to calculate twice
            return data + "*" + ChecksumCalculator.XOR(data);
        }

        //public bool DebugMode { get; set; } = false;

        /// <summary>
        /// Creates a new, empty NMEA sentence.
        /// </summary>
        public NmeaSentence() {}

        /// <summary>
        /// Creates a `NmeaSentence` from a string. Will parse the prefix, data
        /// elements, and also valide the checksum. If the checksum is invalid,
        /// it will throw an `ArgumentException`, therefore this should be used
        /// in a `try`/`catch` block.
        /// </summary>
        /// <param name="sentence">A NMEA sentence string.</param>
        /// <returns>A `NmeaSentence` class representing with the NMEA
        /// information loaded.</returns>
        public static NmeaSentence From(string sentence)
        {
            NmeaSentence newSentence = new NmeaSentence();

            if (string.IsNullOrWhiteSpace(sentence)) {
                throw new ArgumentException("Empty sentence. Nothing to parse.");
            }

            var checksumLocation = sentence.LastIndexOf('*');
            if (checksumLocation > 0) {
                // extract the data from the sentence
                var checksumString = sentence.Substring(checksumLocation + 1);
                var messageData = sentence.Substring(0, checksumLocation);
                byte parsedChecksum;
                // calculate the checksum (have to remove the first character, the "$")
                byte calculatedChecksum = ChecksumCalculator.XOR(messageData.Substring(1));
                try {
                    parsedChecksum = Convert.ToByte(checksumString.Trim(), 16);
                } catch (Exception e) {
                    throw new ArgumentException($"Checksum failed to parse, error: {e.Message}");
                }

                //if (DebugMode) {
                    //Console.WriteLine($"checksum in NMEA:'{checksumString}'");
                    //Console.WriteLine($"parsed checksum:{parsedChecksum:x}");
                    //Console.WriteLine($"actualData:{messageData}");
                    //Console.WriteLine($"Checksum match? {(calculatedChecksum == parsedChecksum ? "yes" : "no")}");
                //}

                // make sure data is good
                if (calculatedChecksum == parsedChecksum) {
                    // split the sentence data up by commas
                    var elements = messageData.Split(',').AsSpan<string>();
                    if (elements.Length <= 0) {
                        throw new ArgumentException("No data in sentence.");
                    }
                    // store the data
                    newSentence.Prefix = elements[0];
                    newSentence.DataElements.Clear();
                    newSentence.DataElements.AddRange(elements.Slice(1).ToArray());
                } else {
                    throw new ArgumentException("Checksum does not match data. Invalid data.");
                }
            } else {
                throw new ArgumentException("No checksum found. Invalid data.");
            }
            return newSentence;
        }
    }
}
