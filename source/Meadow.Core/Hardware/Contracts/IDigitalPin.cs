﻿using System;
namespace Meadow.Hardware
{
    public interface IDigitalPin : IPin, IDigitalChannel
    {
        IGPIOManager GPIOManager { get; }
    }
}
