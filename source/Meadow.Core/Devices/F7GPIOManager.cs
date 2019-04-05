﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using Meadow.Core;
using Meadow.Hardware;
using static Meadow.Core.Interop;

namespace Meadow.Devices
{
    public partial class F7GPIOManager : IIOController
    {
        public event InterruptHandler Interrupt;

        private const string GPDDriverName = "/dev/upd";

        private object _cacheLock = new object();
        private Thread _ist;

        private Dictionary<string, Tuple<STM32.GpioPort, int, uint>> _portPinCache = new Dictionary<string, Tuple<STM32.GpioPort, int, uint>>();

        private IntPtr DriverHandle { get; }

        internal F7GPIOManager()
        {
            DriverHandle = Interop.Nuttx.open(GPDDriverName, Interop.Nuttx.DriverFlags.ReadOnly);
            if (DriverHandle == IntPtr.Zero || DriverHandle.ToInt32() == -1)
            {
                Console.Write("Failed to open UPD driver");
            }
        }

        public void Initialize()
        {
            Console.Write("Initializing GPIOs...");

            // LEDs are inverse logic - initialize to high/off
            ConfigureOutput(STM32.GpioPort.PortA, 0, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, true);
            ConfigureOutput(STM32.GpioPort.PortA, 1, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, true);
            ConfigureOutput(STM32.GpioPort.PortA, 2, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, true);

            // these are the "unallocated" pins on the meadow
            Console.Write(".");
            ConfigureOutput(STM32.GpioPort.PortI, 9, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortH, 13, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortC, 6, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            Console.Write(".");
            ConfigureOutput(STM32.GpioPort.PortB, 8, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortB, 9, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortC, 7, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            Console.Write(".");
            ConfigureOutput(STM32.GpioPort.PortB, 0, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortB, 1, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortH, 10, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            Console.Write(".");
            ConfigureOutput(STM32.GpioPort.PortC, 9, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortB, 14, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortB, 15, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            Console.Write(".");
            ConfigureOutput(STM32.GpioPort.PortG, 3, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortE, 3, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);

            // these are signals that run to the ESP32
            ConfigureOutput(STM32.GpioPort.PortI, 3, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            Console.Write(".");
            ConfigureOutput(STM32.GpioPort.PortI, 2, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortD, 3, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortI, 0, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            Console.Write(".");
            ConfigureOutput(STM32.GpioPort.PortI, 10, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortF, 7, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortD, 2, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);
            ConfigureOutput(STM32.GpioPort.PortB, 13, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, false);

            Console.WriteLine("done");
        }

        /// <summary>
        /// Sets the value of a discrete (digital output)
        /// </summary>
        /// <param name="pin">Pin.</param>
        /// <param name="value">If set to <c>true</c> value.</param>
        void IIOController.SetDiscrete(IPin pin, bool value)
        {
            var designator = GetPortAndPin(pin);

            // invert values for LEDs so they make human sense (low == on on the Meadow)
            switch(designator.port)
            {
                case STM32.GpioPort.PortA:
                    switch(designator.pin)
                    {
                        case 0:
                        case 1:
                        case 2:
                            value = !value;
                            break;
                    }
                    break;
            }

            var register = new Interop.Nuttx.UpdRegisterValue
            {
                Address = designator.address + STM32.STM32_GPIO_BSRR_OFFSET
            };

            if (value)
            {
                register.Value = 1u << designator.pin;
            }
            else
            {
                register.Value = 1u << (designator.pin + 16);
            }

            // write the register
            //            Console.WriteLine($"Writing {register.Value:X} to register: {register.Address:X}");
            var result = Interop.Nuttx.ioctl(DriverHandle, Interop.Nuttx.UpdIoctlFn.SetRegister, ref register);
            if (result != 0)
            {
                Console.WriteLine($"Write failed: {result}");
            }
        }

        /// <summary>
        /// Gets the value of a discrete (digital input)
        /// </summary>
        /// <returns><c>true</c>, if discrete was gotten, <c>false</c> otherwise.</returns>
        /// <param name="pin">Pin.</param>
        public bool GetDiscrete(IPin pin)
        {
            var designator = GetPortAndPin(pin);

            Interop.Nuttx.TryGetRegister(DriverHandle, designator.address + STM32.STM32_GPIO_IDR_OFFSET, out uint register);

            // each pin is a single bit in the register, check the bit associated with the pin number
            return (register & (1 << designator.pin)) != 0;
        }

        private (STM32.GpioPort port, int pin, uint address) GetPortAndPin(IPin pin)
        {
            var key = pin.Key.ToString();
            STM32.GpioPort port;
            uint address;

            lock (_portPinCache)
            {
                if (_portPinCache.ContainsKey(key))
                {
                    return (_portPinCache[key].Item1, _portPinCache[key].Item2, _portPinCache[key].Item3);
                }
                switch (key[1])
                {
                    case 'A':
                        port = STM32.GpioPort.PortA;
                        address = STM32.GPIOA_BASE;
                        break;
                    case 'B':
                        port = STM32.GpioPort.PortB;
                        address = STM32.GPIOB_BASE;
                        break;
                    case 'C':
                        port = STM32.GpioPort.PortC;
                        address = STM32.GPIOC_BASE;
                        break;
                    case 'D':
                        port = STM32.GpioPort.PortD;
                        address = STM32.GPIOD_BASE;
                        break;
                    case 'E':
                        port = STM32.GpioPort.PortE;
                        address = STM32.GPIOE_BASE;
                        break;
                    case 'F':
                        port = STM32.GpioPort.PortF;
                        address = STM32.GPIOF_BASE;
                        break;
                    case 'G':
                        port = STM32.GpioPort.PortG;
                        address = STM32.GPIOG_BASE;
                        break;
                    case 'H':
                        port = STM32.GpioPort.PortH;
                        address = STM32.GPIOH_BASE;
                        break;
                    case 'I':
                        port = STM32.GpioPort.PortI;
                        address = STM32.GPIOI_BASE;
                        break;
                    case 'J':
                        port = STM32.GpioPort.PortJ;
                        address = STM32.GPIOJ_BASE;
                        break;
                    case 'K':
                        port = STM32.GpioPort.PortK;
                        address = STM32.GPIOK_BASE;
                        break;
                    default:
                        throw new NotSupportedException();
                }

                if (int.TryParse(key.Substring(2), out int pinID))
                {
                    return (port, pinID, address);
                }

                throw new NotSupportedException();
            }
        }

        public void ConfigureOutput(IPin pin, bool initialState)
        {
            ConfigureOutput(pin, STM32.ResistorMode.Float, STM32.GPIOSpeed.Speed_50MHz, STM32.OutputType.PushPull, initialState);
        }

        private Dictionary<string, IPin> _interruptPins = new Dictionary<string, IPin>();

        public void ConfigureInput(
            IPin pin,
            ResistorMode resistorMode,
            InterruptMode interruptMode,
            int debounceDuration,
            int glitchFilterCycleCount
            )
        {
            // translate resistor mode
            STM32.ResistorMode mode32;
            if (resistorMode == ResistorMode.Disabled)
            {
                mode32 = STM32.ResistorMode.Float;
            }
            else if (resistorMode == ResistorMode.PullUp)
            {
                mode32 = STM32.ResistorMode.PullUp;
            }
            else
            {
                mode32 = STM32.ResistorMode.PullDown;
            }

            ConfigureInput(pin, mode32, interruptMode);
        }

        private bool ConfigureInput(IPin pin, STM32.ResistorMode resistor, InterruptMode interruptMode)
        {
            lock (_interruptPins)
            {
                var key = (string)pin.Key;
                if (interruptMode != InterruptMode.None && !_interruptPins.ContainsKey(key))
                {
                    _interruptPins.Add(key, pin);
                }
                else if (interruptMode == InterruptMode.None && _interruptPins.ContainsKey((string)pin.Key))
                {
                    _interruptPins.Remove(key);
                }
            }
            return ConfigureGpio(pin, STM32.GpioMode.Input, resistor, STM32.GPIOSpeed.Speed_2MHz, STM32.OutputType.PushPull, false, interruptMode);
        }

        private bool ConfigureOutput(IPin pin, STM32.ResistorMode resistor, STM32.GPIOSpeed speed, STM32.OutputType type, bool initialState)
        {
            return ConfigureGpio(pin, STM32.GpioMode.Output, resistor, speed, type, initialState, InterruptMode.None);
        }

        private bool ConfigureOutput(STM32.GpioPort port, int pin, STM32.ResistorMode resistor, STM32.GPIOSpeed speed, STM32.OutputType type, bool initialState)
        {
            return ConfigureGpio(port, pin, STM32.GpioMode.Output, resistor, speed, type, initialState, InterruptMode.None);
        }

        private bool ConfigureGpio(IPin pin, STM32.GpioMode mode, STM32.ResistorMode resistor, STM32.GPIOSpeed speed, STM32.OutputType type, bool initialState, InterruptMode interruptMode)
        {
            var designator = GetPortAndPin(pin);

            return ConfigureGpio(designator.port, designator.pin, mode, resistor, speed, type, initialState, interruptMode);
        }

        private bool ConfigureGpio(STM32.GpioPort port, int pin, STM32.GpioMode mode, STM32.ResistorMode resistor, STM32.GPIOSpeed speed, STM32.OutputType type, bool initialState, InterruptMode interruptMode)
        {
            int setting = 0;
            uint base_addr = 0;

            switch (port)
            {
                case STM32.GpioPort.PortA: base_addr = STM32.GPIOA_BASE; break;
                case STM32.GpioPort.PortB: base_addr = STM32.GPIOB_BASE; break;
                case STM32.GpioPort.PortC: base_addr = STM32.GPIOC_BASE; break;
                case STM32.GpioPort.PortD: base_addr = STM32.GPIOD_BASE; break;
                case STM32.GpioPort.PortE: base_addr = STM32.GPIOE_BASE; break;
                case STM32.GpioPort.PortF: base_addr = STM32.GPIOF_BASE; break;
                case STM32.GpioPort.PortG: base_addr = STM32.GPIOG_BASE; break;
                case STM32.GpioPort.PortH: base_addr = STM32.GPIOH_BASE; break;
                case STM32.GpioPort.PortI: base_addr = STM32.GPIOI_BASE; break;
                case STM32.GpioPort.PortJ: base_addr = STM32.GPIOJ_BASE; break;
                case STM32.GpioPort.PortK: base_addr = STM32.GPIOK_BASE; break;
                default: throw new ArgumentException();
            }

            // TODO: we probably need to disable interrupts here (enter critical section)

            ////// ====== MODE ======
            // if this is an output, set the initial state
            if (mode == STM32.GpioMode.Output)
            {
                var state = initialState ? 1u << pin : 1u << (16 + pin);

                Interop.Nuttx.SetRegister(DriverHandle, base_addr + STM32.STM32_GPIO_BSRR_OFFSET, state);
            }

            UpdateConfigRegister2Bit(base_addr + STM32.STM32_GPIO_MODER_OFFSET, (int)mode, pin);

            ////// ====== RESISTOR ======
            setting = 0;
            if (mode != STM32.GpioMode.Analog)
            {
                setting = (int)resistor;
            }
            UpdateConfigRegister2Bit(base_addr + STM32.STM32_GPIO_PUPDR_OFFSET, setting, pin);


            if (mode == STM32.GpioMode.AlternateFunction)
            {
                ////// ====== ALTERNATE FUNCTION ======
                // TODO:
            }

            ////// ====== SPEED ======
            setting = 0;
            if (mode == STM32.GpioMode.AlternateFunction || mode == STM32.GpioMode.Output)
            {
                setting = (int)speed;
            }
            UpdateConfigRegister2Bit(base_addr + STM32.STM32_GPIO_OSPEED_OFFSET, setting, pin);

            ////// ====== OUTPUT TYPE ======
            if (mode == STM32.GpioMode.Output || mode == STM32.GpioMode.AlternateFunction)
            {
                UpdateConfigRegister1Bit(base_addr + STM32.STM32_GPIO_OTYPER_OFFSET, (type == STM32.OutputType.OpenDrain), pin);
            }
            else
            {
                UpdateConfigRegister1Bit(base_addr + STM32.STM32_GPIO_OTYPER_OFFSET, false, pin);
            }


            // TODO INTERRUPTS
            if(interruptMode != InterruptMode.None)
            {
                var cfg = new Interop.Nuttx.UpdGpioInterruptConfiguration()
                {
                    Enable = true,
                    Port = (int)port,
                    Pin = pin,
                    RisingEdge = interruptMode == InterruptMode.EdgeRising || interruptMode == InterruptMode.EdgeBoth,
                    FallingEdge = interruptMode == InterruptMode.EdgeFalling || interruptMode == InterruptMode.EdgeBoth,
                    Irq = ((int)port << 4) | pin
                };

                if(_ist == null)
                {
                    _ist = new Thread(InterruptServiceThreadProc)
                    {
                        IsBackground = true
                    };

                    _ist.Start();
                }

                Console.WriteLine("Calling ioctl to enable interrupts");

                var result = Interop.Nuttx.ioctl(DriverHandle, Nuttx.UpdIoctlFn.RegisterGpioIrq, ref cfg);
            }
            else
            {
                // TODO: disable interrupt if it was enabled
            }

            return true;
        }

        private void InterruptServiceThreadProc(object o)
        {
            IntPtr queue = Interop.Nuttx.mq_open(new StringBuilder("/mdw_int"), Nuttx.QueueOpenFlag.ReadOnly);
            Console.WriteLine($"IST Started reading queue {queue.ToInt32():X}");

            var rx_buffer = new byte[16];

            while (true)
            {
                int priority = 0;
                var result = Interop.Nuttx.mq_receive(queue, rx_buffer, rx_buffer.Length, ref priority);
//                Console.WriteLine("queue data arrived");

                if (result >= 0)
                {
                    var irq = BitConverter.ToInt32(rx_buffer, 0);
                    var port = irq >> 4;
                    var pin = irq & 0xf;
                    var key = $"P{(char)(65 + port)}{pin}";

//                    Console.WriteLine($"Interrupt on {key}");
                    lock (_interruptPins)
                    {
                        if (_interruptPins.ContainsKey(key))
                        {
                            Interrupt?.Invoke(_interruptPins[key]);
                        }
                    }
                }
            }
        }

        private bool UpdateConfigRegister1Bit(uint address, bool value, int pin)
        {
            if (!Interop.Nuttx.TryGetRegister(DriverHandle, address, out uint register))
            {
                return false;
            }

            var temp = register;
            if (value)
            {
                temp |= (1u << pin);
            }
            else
            {
                temp &= ~(1u << pin);
            }

            // write the register
            return Interop.Nuttx.SetRegister(DriverHandle, address, temp);
        }

        private bool UpdateConfigRegister2Bit(uint address, int value, int pin)
        {
            return Interop.Nuttx.UpdateRegister(DriverHandle, address, 0, (uint)(value & 3) << (pin << 1));
        }

        private bool UpdateConfigRegister2Bit_old(uint address, int value, int pin)
        {
            var register = new Interop.Nuttx.UpdRegisterValue();
            register.Address = address;
            //            Console.WriteLine($"Reading register: {register.Address:X}");
            var result = Interop.Nuttx.ioctl(DriverHandle, Interop.Nuttx.UpdIoctlFn.GetRegister, ref register);
            if (result != 0)
            {
                Console.WriteLine($"Read failed: {result}");
                return false;
            }
            //            Console.WriteLine($"Value: {register.Value:X}");

            var temp = register.Value;
            // mask off the bits we're interested in
            temp &= ~(3u << pin);
            // set the register bits
            temp |= (uint)value << (pin << 1);
            // write the register
            register.Value = temp;
            //            Console.WriteLine($"Writing {register.Value:X} to register: {register.Address:X}");
            result = Interop.Nuttx.ioctl(DriverHandle, Interop.Nuttx.UpdIoctlFn.SetRegister, ref register);
            if (result != 0)
            {
                Console.WriteLine($"Write failed: {result}");
                return false;
            }
            return true;
        }
    }

    /* ===== MEADOW GPIO PIN MAP =====
        BOARD PIN   SCHEMATIC       CPU PIN   MDW NAME  ALT FN   IMPLEMENTED?
        J301-1      RESET                       
        J301-2      3.3                       
        J301-3      VREF                       
        J301-4      GND                       
        J301-5      DAC_OUT1        PA4         A0
        J301-6      DAC_OUT2        PA5         A1
        J301-7      ADC1_IN3        PA3         A2
        J301-8      ADC1_IN7        PA7         A3
        J301-9      ADC1_IN10       PC0         A4
        J301-10     ADC1_IN11       PC1         A5
        J301-11     SPI3_CLK        PC10        SCK
        J301-12     SPI3_MOSI       PB5         MOSI    AF6
        J301-13     SPI3_MISO       PC11        MISO    AF6
        J301-14     UART4_RX        PI9         D00     AF8
        J301-15     UART4_TX        PH13        D01     AF8
        J301-16     PC6             PC6         D02                 *
        J301-17     CAN1_RX         PB8         D03     AF9
        J301-18     CAN1_TX         PB9         D04     AF9

        J302-4      PE3             PE3         D15
        J302-5      PG3             PG3         D14
        J302-6      USART1_RX       PB15        D13     AF4
        J302-7      USART1_TX       PB14        D12     AF4
        J302-8      PC9             PC9         D11
        J302-9      PH10            PH10        D10
        J302-10     PB1             PB1         D09
        J302-11     I2C1_SCL        PB6         D08     AF4
        J302-12     I2C1_SDA        PB7         D07     AF4
        J302-13     PB0             PB0         D06
        J302-14     PC7             PC7         D05

        LED_B       PA0
        LED_G       PA1
        LED_R       PA2
    */
}
