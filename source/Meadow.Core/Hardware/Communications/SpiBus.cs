﻿using Meadow.Devices;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using static Meadow.Core.Interop;

namespace Meadow.Hardware
{
    /// <summary>
    /// Represents an SPI communication bus for communicating to peripherals that 
    /// implement the SPI protocol.
    /// </summary>
    public partial class SpiBus : ISpiBus
    {
        private SemaphoreSlim _busSemaphore = new SemaphoreSlim(1, 1);

        ///// <summary>
        ///// SPI bus object.
        ///// </summary>
        //private static Spi _spi;

        /// <summary>
        /// Configuration to use for this instance of the SPIBus.
        /// </summary>
        public SpiBus.ConfigurationOptions Configuration { get; protected set; }

        /// <summary>
        /// Default constructor for the SPIBus.
        /// </summary>
        /// <remarks>
        /// This is private to prevent the programmer using it.
        /// </remarks>
        protected SpiBus()
        {
        }

        // TODO: Call from Device.CreateSpiBus
        // TODO: use Spi.Configuration configuration? don't we already know this, as its chip specific?
        // TODO: we should already know clock phase and polarity, yeah?
        internal static SpiBus From(
            IPin clock,
            IPin mosi,
            IPin miso,
            ushort speed = 1000,
            byte cpha = 0,
            byte cpol = 0)
        {
            return new SpiBus();
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public void SendData(IPin chipSelect, params byte[] data)
        {
            SendData(chipSelect, data);
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public void SendData(IPin chipSelect, IEnumerable<byte> data)
        {
            SendData(chipSelect, data.ToArray());
        }

        private void SendData(IPin chipSelect, byte[] data)
        {
            var gch = GCHandle.Alloc(data, GCHandleType.Pinned);

            _busSemaphore.Wait();

            try
            {
                var command = new Nuttx.UpdSPICommand()
                {
                    BufferLength = data.Length,
                    TxBuffer = gch.AddrOfPinnedObject(),
                    RxBuffer = IntPtr.Zero
                };

                Console.Write(" +SendData");
                var result = UPD.Ioctl(Nuttx.UpdIoctlFn.SPIData, ref command);
                Console.WriteLine($" returned {result}");
            }
            finally
            {
                _busSemaphore.Release();

                if (gch.IsAllocated)
                {
                    gch.Free();
                }
            }
        }

        public byte[] ReceiveData(IPin chipSelect, int numberOfBytes)
        {
            var rxBuffer = new byte[numberOfBytes];
            var gch = GCHandle.Alloc(rxBuffer, GCHandleType.Pinned);

            _busSemaphore.Wait();

            try
            {
                var command = new Nuttx.UpdSPICommand()
                {
                    TxBuffer = IntPtr.Zero,
                    BufferLength = rxBuffer.Length,
                    RxBuffer = gch.AddrOfPinnedObject(),
                };

                Console.Write(" +ReadData");
                var result = UPD.Ioctl(Nuttx.UpdIoctlFn.SPIData, ref command);
                Console.WriteLine($" returned {result}");

                return rxBuffer;
            }
            finally
            {
                _busSemaphore.Release();

                if (gch.IsAllocated)
                {
                    gch.Free();
                }
            }
        }

        public byte[] ExchangeData(IPin chipSelect, params byte[] dataToWrite)
        {
            var rxBuffer = new byte[dataToWrite.Length];
            var rxGch = GCHandle.Alloc(rxBuffer, GCHandleType.Pinned);
            var txGch = GCHandle.Alloc(dataToWrite, GCHandleType.Pinned);

            _busSemaphore.Wait();

            try
            {
                var command = new Nuttx.UpdSPICommand()
                {
                    BufferLength = dataToWrite.Length,
                    TxBuffer = txGch.AddrOfPinnedObject(),
                    RxBuffer = rxGch.AddrOfPinnedObject(),
                };

                var result = UPD.Ioctl(Nuttx.UpdIoctlFn.SPIData, ref command);

                return rxBuffer;
            }
            finally
            {
                _busSemaphore.Release();

                if (rxGch.IsAllocated)
                {
                    rxGch.Free();
                }
                if (txGch.IsAllocated)
                {
                    txGch.Free();
                }
            }
        }

        ///// <summary>
        ///// Create a new SPIBus object using the requested clock phase and polarity.
        ///// </summary>
        ///// <param name="cpha">CPHA - Clock Phase (0 or 1).</param>
        ///// <param name="cpol">CPOL - Clock Polarity (0 or 1).</param>
        ///// <param name="speed">Speed of the SPI bus.</param>
        //protected SpiBus(ushort speed = 1000, byte cpha = 0, byte cpol = 0)
        //{
        //    Configure(module, chipSelect, cpha, cpol, speed);
        //    //_spi = new Spi(Configuration);
        //}

        ///// <summary>
        ///// Create a new SPIBus operating in the specified mode.
        ///// </summary>
        ///// <remarks>
        /////     Mode    CPOL    CPHA
        /////     0       0       0
        /////     1       0       1
        /////     2       1       0
        /////     3       1       1
        ///// </remarks>
        ///// <param name="module">SPI module to configure.</param>
        ///// <param name="chipSelect">Chip select pin.</param>
        ///// <param name="mode">SPI Bus Mode - should be in the range 0 - 3.</param>
        ///// <param name="speed">Speed of the SPI bus.</param>
        //public SpiBus(Spi.SPI_module module, IPin chipSelect, byte mode, ushort speed)
        //{
        //    if (mode > 3) {
        //        throw new ArgumentException("SPI Mode should be in the range 0 - 3.");
        //    }
        //    byte cpha = 0;
        //    byte cpol = 0;
        //    switch (mode) {
        //        case 1:
        //            cpha = 1;
        //            break;
        //        case 2:
        //            cpol = 1;
        //            break;
        //        case 3:
        //            cpol = 1;
        //            cpha = 1;
        //            break;
        //    }
        //    Configure(module, chipSelect, cpha, cpol, speed);
        //    _spi = new Spi(Configuration);
        //}


        ///// <summary>
        ///// Works out how the SPI bus should be configured from the clock polarity and phase.
        ///// </summary>
        ///// <param name="module">SPI module to configure.</param>
        ///// <param name="chipSelect">Chip select pin.</param>
        ///// <param name="cpha">CPHA - Clock phase (0 or 1).</param>
        ///// <param name="cpol">CPOL - Clock polarity (0 or 1).</param>
        ///// <param name="speed">Speed of the SPI bus.</param>
        ///// <returns>SPI Configuration object.</returns>
        //private void Configure(Spi.SPI_module module, IPin chipSelect, byte cpha, byte cpol,
        //    ushort speed)
        //{
        //    if (cpha > 1) {
        //        throw new ArgumentException("Clock phase should be 0 to 1.");
        //    }
        //    if (cpol > 1) {
        //        throw new ArgumentException("Clock polarity should be 0 to 1.");
        //    }
        //    Configuration = new Spi.Configuration(SPI_mod: module,
        //                                       ChipSelect_Port: chipSelect,
        //                                       ChipSelect_ActiveState: false,
        //                                       ChipSelect_SetupTime: 0,
        //                                       ChipSelect_HoldTime: 0,
        //                                       Clock_IdleState: (cpol == 1),
        //                                       Clock_Edge: (cpha == 1),
        //                                       Clock_RateKHz: speed);
        //}

        /*
    /// <summary>
    /// Write a single byte to the peripheral.
    /// </summary>
    /// <param name="value">Value to be written (8-bits).</param>
    public void WriteByte(IDigitalOutputPort chipSelect, byte value)
    {
        WriteBytes(chipSelect, new[] { value });
    }

    /// <summary>
    /// Write a number of bytes to the peripheral.
    /// </summary>
    /// <remarks>
    /// The number of bytes to be written will be determined by the length of the byte array.
    /// </remarks>
    /// <param name="values">Values to be written.</param>
    public void WriteBytes(IDigitalOutputPort chipSelect, byte[] values)
    {
        //_spi.Config = Configuration;
        //_spi.Write(values);
    }

    /// <summary>
    /// Write an unsigned short to the peripheral.
    /// </summary>
    /// <param name="address">Address to write the first byte to.</param>
    /// <param name="value">Value to be written (16-bits).</param>
    /// <param name="order">Indicate if the data should be written as big or little endian.</param>
    public void WriteUShort(IDigitalOutputPort chipSelect, byte address, ushort value,
        ByteOrder order = ByteOrder.LittleEndian)
    {
        var data = new byte[2];
        if (order == ByteOrder.LittleEndian) {
            data[0] = (byte)(value & 0xff);
            data[1] = (byte)((value >> 8) & 0xff);
        } else {
            data[0] = (byte)((value >> 8) & 0xff);
            data[1] = (byte)(value & 0xff);
        }
        WriteRegisters(chipSelect, address, data);
    }

    /// <summary>
    /// Write a number of unsigned shorts to the peripheral.
    /// </summary>
    /// <remarks>
    /// The number of bytes to be written will be determined by the length of the byte array.
    /// </remarks>
    /// <param name="address">Address to write the first byte to.</param>
    /// <param name="values">Values to be written.</param>
    /// <param name="order">Indicate if the data should be written as big or little endian.</param>
    public void WriteUShorts(IDigitalOutputPort chipSelect, byte address, ushort[] values,
        ByteOrder order = ByteOrder.LittleEndian)
    {
        var data = new byte[2 * values.Length];
        for (var index = 0; index < values.Length; index++) {
            if (order == ByteOrder.LittleEndian) {
                data[index * 2] = (byte)(values[index] & 0xff);
                data[(index * 2) + 1] = (byte)((values[index] >> 8) & 0xff);
            } else {
                data[index * 2] = (byte)((values[index] >> 8) & 0xff);
                data[(index * 2) + 1] = (byte)(values[index] & 0xff);
            }
        }
        WriteRegisters(chipSelect, address, data);
    }

    /// <summary>
    /// Write data a register in the peripheral.
    /// </summary>
    /// <param name="address">Address of the register to write to.</param>
    /// <param name="value">Data to write into the register.</param>
    public void WriteRegister(IDigitalOutputPort chipSelect, byte address, byte value)
    {
        WriteRegisters(chipSelect, address, new[] { value });
    }

    /// <summary>
    /// Write data to one or more registers.
    /// </summary>
    /// <param name="address">Address of the first register to write to.</param>
    /// <param name="data">Data to write into the registers.</param>
    public void WriteRegisters(IDigitalOutputPort chipSelect, byte address, byte[] values)
    {
        var data = new byte[values.Length + 1];
        data[0] = address;
        Array.Copy(values, 0, data, 1, values.Length);
        WriteBytes(chipSelect, data);
    }

    /// <summary>
    /// Write data to the peripheral and also read some data from the peripheral.
    /// </summary>
    /// <remarks>
    /// The number of bytes to be written and read will be determined by the length of the byte arrays.
    /// </remarks>
    /// <param name="write">Array of bytes to be written to the device.</param>
    /// <param name="length">Amount of data to read from the device.</param>
    public byte[] WriteRead(IDigitalOutputPort chipSelect, byte[] write, ushort length)
    {
        var result = new byte[length];
        //Config = Configuration;
        //WriteRead(chipSelect, write, result);
        //return result;
        return new byte[] { 0 };
    }

    /// <summary>
    /// Read the specified number of bytes from the I2C peripheral.
    /// </summary>
    /// <returns>The bytes.</returns>
    /// <param name="numberOfBytes">Number of bytes.</param>
    public byte[] ReadBytes(IDigitalOutputPort chipSelect, ushort numberOfBytes)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Read a registers from the peripheral.
    /// </summary>
    /// <param name="address">Address of the register to read.</param>
    public byte ReadRegister(IDigitalOutputPort chipSelect, byte address)
    {
        return WriteRead(chipSelect, new[] { address }, 1)[0];
    }

    /// <summary>
    /// Read one or more registers from the peripheral.
    /// </summary>
    /// <param name="address">Address of the first register to read.</param>
    /// <param name="length">Number of bytes to read from the device.</param>
    public byte[] ReadRegisters(IDigitalOutputPort chipSelect, byte address, ushort length)
    {
        return WriteRead(chipSelect, new[] { address }, length);
    }

    /// <summary>
    /// Read an unsigned short from a pair of registers.
    /// </summary>
    /// <param name="address">Register address of the low byte (the high byte will follow).</param>
    /// <param name="order">Order of the bytes in the register (little endian is the default).</param>
    /// <returns>Value read from the register.</returns>
    public ushort ReadUShort(IDigitalOutputPort chipSelect, byte address,
        ByteOrder order = ByteOrder.LittleEndian)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Read the specified number of unsigned shorts starting at the register
    /// address specified.
    /// </summary>
    /// <param name="address">First register address to read from.</param>
    /// <param name="number">Number of unsigned shorts to read.</param>
    /// <param name="order">Order of the bytes (Little or Big endian)</param>
    /// <returns>Array of unsigned shorts.</returns>
    public ushort[] ReadUShorts(IDigitalOutputPort chipSelect, byte address, ushort number,
        ByteOrder order = ByteOrder.LittleEndian)
    {
        throw new NotImplementedException();
    }
    */
    }
}