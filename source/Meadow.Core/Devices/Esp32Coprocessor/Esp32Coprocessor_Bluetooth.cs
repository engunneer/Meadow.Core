﻿using System;
using System.Runtime.InteropServices;
using Meadow.Devices.Esp32.MessagePayloads;
using Meadow.Gateways;
using static Meadow.Core.Interop;

namespace Meadow.Devices
{
    public partial class Esp32Coprocessor : IBluetoothAdapter
    {
        internal string GetDefaultName()
        {
            // TODO: query this
            return "Meadow BLE";
        }

        public bool StartBluetoothStack(string configuration)
        {
            if (string.IsNullOrWhiteSpace(configuration))
            {
                throw new ArgumentException("Invalid deviceName");
            }

            // TODO: sanity checking of the config

            var payloadGcHandle = default(GCHandle);

            try
            {
                var req = new BTStackConfig
                {
                    Config = configuration
                };

                var requestBytes = Encoders.EncodeBTStackConfig(req);

                // TODO: do we expect a result?  If so create a buffer and pin it.

                payloadGcHandle = GCHandle.Alloc(requestBytes, GCHandleType.Pinned);

                var command = new Nuttx.UpdEsp32Command()
                {
                    Interface = (byte)Esp32Interfaces.BlueTooth,
                    Function = (int)BluetoothFunction.Start,
                    StatusCode = (int)StatusCodes.CompletedOk,
                    Payload = payloadGcHandle.AddrOfPinnedObject(),
                    PayloadLength = (UInt32)requestBytes.Length,
                    Result = IntPtr.Zero,
                    ResultLength = 0,
                    Block = 1
                };

                var result = UPD.Ioctl(Nuttx.UpdIoctlFn.Esp32Command, ref command);

                if ((result == 0) && (command.StatusCode == (UInt32)StatusCodes.CompletedOk))
                {
                    return true;
                }
                else
                {
                    if (command.StatusCode == (UInt32)StatusCodes.CoprocessorNotResponding)
                    {
                        throw new Exception("ESP32 coprocessor is not responding.");
                    }

                    // TODO: if we have a response, we'd decode that here

                    return false;
                }
            }
            finally
            {
                if (payloadGcHandle.IsAllocated)
                {
                    payloadGcHandle.Free();
                }
            }
        }
    }
}