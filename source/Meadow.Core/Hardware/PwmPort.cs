﻿using Meadow.Devices;
using Meadow.Hardware;
using System;
using System.Linq;
using static Meadow.Core.Interop;

namespace Meadow.Hardware
{
    /// <summary>
    /// Represents a port that is capable of generating a Pulse-Width-Modulation
    /// signal; which approximates an analog output via digital pulses.
    /// </summary>
    public class PwmPort : PwmPortBase
    {
        private bool _isRunning = false;
        private float _frequency;
        private float _dutyCycle;
        private bool _inverted;

        protected IIOController IOController { get; set; }
        protected IPwmChannelInfo PwmChannelInfo { get; set; }

        protected PwmPort(
            IPin pin,
            IIOController ioController,
            IPwmChannelInfo channel,
            bool inverted = false)
            : base(pin, channel)
        {
            this.IOController = ioController;
            this.PwmChannelInfo = channel;
            this.Inverted = inverted;
        }

        internal static PwmPort From(
            IPin pin,
            IIOController ioController,
            float frequency = 100,
            float dutyCycle = 0.5f,
            bool inverted = false)
        {
            var channel = pin.SupportedChannels.OfType<IPwmChannelInfo>().FirstOrDefault();
            if (channel != null)
            {
                var port = new PwmPort(pin, ioController, channel);
                port.TimeScale = TimeScale.Seconds;
                port.Frequency = frequency;
                port.DutyCycle = dutyCycle;
                port.Inverted = inverted;

                return port;
            }
            else
            {
                throw new Exception("Unable to create an output port on the pin, because it doesn't have a PWM channel");
            }
        }

        /// <summary>
        /// When <b>true</b> Duty Cycle is "percentage of time spent low" rather than high.
        /// </summary>
        public override bool Inverted
        {
            get => _inverted;
            set
            {
                if (value == Inverted) return;
                _inverted = value;
                if (State)
                {
                    UpdateChannel();
                }
            }
        }

        /// <summary>
        /// The frequency, in Hz (cycles per second) of the PWM square wave.
        /// </summary>
        public override float Frequency
        {
            get => _frequency;
            set
            {
                if (value <= 0) throw new ArgumentOutOfRangeException();

                // TODO: do we have a lower or upper bound on this hardware?

                if (value == Frequency) return;

                _frequency = value;
                if (State)
                {
                    UpdateChannel();
                }
            }
        }

        /// <summary>
        /// The percentage of time the PWM pulse is high (in the range of 0.0 to 1.0)
        /// </summary>
        public override float DutyCycle
        {
            get => _dutyCycle;
            set
            {
                if (value < 0.0 || value > 1.0) throw new ArgumentOutOfRangeException("Duty cycle must be between 0.0 and 1.0");
                if (value == DutyCycle) return;

                _dutyCycle = value;
                if (State)
                {
                    UpdateChannel();
                }
            }
        }
    
        /// <summary>
        /// The amount of time, in seconds, that the a PWM pulse is high.  This will always be less than or equal to the Period
        /// </summary>
        public override float Duration
        {
            get => DutyCycle * Period;
            set
            {
                if (value > Period) throw new ArgumentOutOfRangeException("Duration must be less than Period");
                if (value < 0) throw new ArgumentOutOfRangeException("Duration cannot be negative");

                DutyCycle = value / Period;
            }
        }

        /// <summary>
        /// The reciprocal of the PWM frequency - in seconds.
        /// </summary>
        public override float Period
        {
            get => 1.0f / Frequency * (float)TimeScale;
            set
            {
                Frequency = 1.0f / value / (float)TimeScale;
            }
        }

        private void UpdateChannel()
        {
            UPD.PWM.Start(PwmChannelInfo, (uint)Frequency, Inverted ? (1.0f - DutyCycle) : DutyCycle);
        }


        /// <summary>
        /// Returns <b>true</b> if the PWM is currently running, otherwise <b>false</b>
        /// </summary>
        public override bool State
        {
            get => _isRunning;
        }

        /// <summary>
        /// Starts the PWM output
        /// </summary>
        public override void Start()
        {
            UpdateChannel();
            _isRunning = true;
        }

        /// <summary>
        /// Stops the PWM output
        /// </summary>
        public override void Stop()
        {
            UPD.PWM.Stop(PwmChannelInfo);
            _isRunning = false;
        }

        protected void Dispose(bool disposing)
        {
            Stop();
            UPD.PWM.Shutdown(PwmChannelInfo.Timer);
        }

        /// <summary>
        /// Disposes the resources associated with the PwmPort
        /// </summary>
        public override void Dispose()
        {
            Dispose(true);
        }
    }
}