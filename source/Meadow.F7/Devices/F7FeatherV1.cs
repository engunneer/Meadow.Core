﻿using Meadow.Hardware;
using Meadow.Units;
using System;

namespace Meadow.Devices
{
    [Obsolete("Use the F7FeatherV1 class instead.")]
    public class F7Micro : F7FeatherV1
    {
    }

    /// <summary>
    /// Represents a Meadow F7 micro device. Includes device-specific IO mapping,
    /// capabilities and provides access to the various device-specific features.
    /// </summary>
    public partial class F7FeatherV1 : F7FeatherBase
    {
        public F7FeatherV1()
            : base(
                  new Pinout(),
                  new F7FeatherGpioManager(),
                  new AnalogCapabilities(true, DefaultA2DResolution),
                  new NetworkCapabilities(true, false))
        {
            if (this.Information.Platform != Hardware.MeadowPlatform.F7FeatherV1)
            {
                var message = $"Application is defined as F7FeatherV1, but running hardware is {this.Information.Platform}";
                Resolver.Log.Error(message);
                throw new UnsupportedPlatformException(this.Information.Platform, message);
            }
        }

        public override BatteryInfo GetBatteryInfo()
        {
            if (Coprocessor != null)
            {
                return new BatteryInfo
                {
                    Voltage = new Voltage(Coprocessor.GetBatteryLevel(), Voltage.UnitType.Volts)
                };
            }

            throw new Exception("Coprocessor not initialized.");
        }

        protected override int GetI2CBusNumberForPins(IPin clock, IPin data)
        {
            if (clock.Name == (Pins as F7FeatherV1.Pinout)?.I2C_SCL.Name)
            {
                return 1;
            }

            // this is an unsupported bus, but will get caught elsewhere
            return -1;
        }
    }
}