﻿using System;
using System.Collections.Generic;

namespace Meadow.Hardware
{
    public enum ChipSelectMode
    {
        ActiveLow,
        ActiveHigh
    }

    public interface ISpiBus
    {
        long[] SupportedSpeeds { get; }

        SpiClockConfiguration Configuration { get; }

        void SendData(IDigitalOutputPort chipSelect, params byte[] data);
        void SendData(IDigitalOutputPort chipSelect, IEnumerable<byte> data);
        byte[] ReceiveData(IDigitalOutputPort chipSelect, int numberOfBytes);

        void SendData(IDigitalOutputPort chipSelect, ChipSelectMode csMode, params byte[] data);
        void SendData(IDigitalOutputPort chipSelect, ChipSelectMode csMode, IEnumerable<byte> data);
        byte[] ReceiveData(IDigitalOutputPort chipSelect, ChipSelectMode csMode, int numberOfBytes);

        [Obsolete("Use the `Span<byte>` overload instead.")]
        void ExchangeData(IDigitalOutputPort chipSelect, ChipSelectMode csMode, byte[] sendBuffer, byte[] receiveBuffer);
        [Obsolete("Use the `Span<byte>` overload instead.")]
        void ExchangeData(IDigitalOutputPort chipSelect, ChipSelectMode csMode, byte[] sendBuffer, byte[] receiveBuffer, int bytesToExchange);

        // new stuff
        void SendData(IDigitalOutputPort chipSelect, Span<byte> data);
        void SendData(IDigitalOutputPort chipSelect, ChipSelectMode csMode, Span<byte> data);
        void ExchangeData(IDigitalOutputPort chipSelect, ChipSelectMode csMode, Span<byte> sendBuffer, Span<byte> receiveBuffer);
        void ExchangeData(IDigitalOutputPort chipSelect, ChipSelectMode csMode, Span<byte> sendBuffer, Span<byte> receiveBuffer, int bytesToExchange);
    }
}
