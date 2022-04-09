﻿using Meadow.Hardware;
using Meadow.Units;
using System;

namespace Meadow.Simulation
{
    internal class SimulatedDigitalInputPort : DigitalInputPortBase, IDigitalInterruptPort
    {
        private SimulatedPin _pin;

        public SimulatedDigitalInputPort(IPin pin, IDigitalChannelInfo channel, InterruptMode interruptMode = InterruptMode.None) 
            : base(pin, channel, interruptMode)
        {
            _pin = pin as SimulatedPin;
            _pin.VoltageChanged += OnPinVoltageChanged;
        }

        private void OnPinVoltageChanged(object sender, EventArgs e)
        {
            RaiseChangedAndNotify(new DigitalPortResult(new DigitalState(State, DateTime.Now), null));
        }

        internal void SetVoltage(Voltage voltage)
        {
            if (voltage == _pin.Voltage) return;

            _pin.Voltage = voltage;
        }

        public override bool State { get => _pin.Voltage >= SimulationEnvironment.ActiveVoltage; }

        public override ResistorMode Resistor { get; set; }
        public override double DebounceDuration { get; set; }
        public override double GlitchDuration { get; set; }


        public override void Dispose()
        {
        }
    }
}
