﻿using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Meadow;
using Meadow.Devices;
using Meadow.Hardware;


namespace MeadowApp
{
    public class MeadowApp : App<F7Micro, MeadowApp>
    {
        ISerialPort classicSerialPort;

        public MeadowApp()
        {
            Console.WriteLine("SimpleSerial_Test");
            Initialize();

            Console.WriteLine("BUGBUG: this test fails under specific conditions. See test for info.");
            SimpleReadWriteTest();
            Console.WriteLine("Simple read/write testing completed.");

            SerialEventTest().Wait();
            Console.WriteLine("Serial event testing completed.");
        }

        void Initialize()
        {
            // instantiate our serial port
            this.classicSerialPort = Device.CreateSerialPort(
                Device.SerialPortNames.Com1, 115200);
            Console.WriteLine("\tCreated");

            // open the serial port
            this.classicSerialPort.Open();
            Console.WriteLine("\tOpened");

        }

        /// <summary>
        /// Tests basic reading of serial in which the Write.Length == Read.Count
        /// </summary>
        void SimpleReadWriteTest()
        {
            int count = 10;

            //Span<byte> buffer = new byte[512];
            byte[] buffer = new byte[512];

            // run the test a few times
            int dataLength = 0;
            for (int i = 0; i < 10; i++) {
                Console.WriteLine("Writing data...");
                dataLength = this.classicSerialPort.Write(Encoding.ASCII.GetBytes($"{ count * i } PRINT Hello Meadow!"));

                // give some time for the electrons to electronify
                // TODO/HACK/BUGBUG: reduce this to 100ms and weird stuff happens;
                // specifically we get the following output, and i don't know why:
                // Writing data...
                // Serial data: 0 PRINT Hello Meadow!
                // Writing data...
                // Serial data: 0 PRINT Hello Meadow!
                // Writing data...
                // Serial data: 10 PRINT Hello Meadow!
                // Writing data...
                // Serial data: 20 PRINT Hello Meadow!
                // ...
                // how is it possible that the first line is there twice, even
                // though we're clearing it out??
                Thread.Sleep(300);

                // empty it out
                //int dataLength = this.classicSerialPort.BytesToRead;
                this.classicSerialPort.Read(buffer, 0, dataLength);

                Console.WriteLine($"Serial data: {Encoding.ASCII.GetString(buffer, 0, dataLength)}");

                Thread.Sleep(300);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        void AsyncReadWriteTest()
        {
            // 
        }

        // TODO: Someone smarter than me (bryan) needs to review this and determine
        // if my use of Span<T> is actually saving anything here.
        async Task SerialEventTest()
        {
            Console.WriteLine("SerialEventTest");

            // wire up the event handler
            //this.classicSerialPort.DataReceived += async (s,e) => {
            //    Console.WriteLine("Serial Data Received");
            //    byte[] buffer = new byte[512];
            //    while (true) { 
            //        int readCount = await classicSerialPort.Read(buffer, 0, 512);
            //        Console.Write(ParseToString(buffer, readCount));
            //        // if we got all the data, break the while loop, otherwise, keep going.
            //        if(readCount < 512) { break; }
            //    }
            //    Console.Write("\n");
            //};

            this.classicSerialPort.DataReceived += ProcessData;

            // send some messages
            await Task.Run(async () => {
                Console.WriteLine("Sending 8 messages of profundity.");
                this.classicSerialPort.Write(Encoding.ASCII.GetBytes("Ticking away the moments that make up a dull day,"));
                await Task.Delay(100);
                this.classicSerialPort.Write(Encoding.ASCII.GetBytes("fritter and waste the hours in an offhand way."));
                await Task.Delay(100);
                this.classicSerialPort.Write(Encoding.ASCII.GetBytes("Kicking around on a piece of ground in your home town,"));
                await Task.Delay(100);
                this.classicSerialPort.Write(Encoding.ASCII.GetBytes("Waiting for someone or something to show you the way."));
                await Task.Delay(100);
                this.classicSerialPort.Write(Encoding.ASCII.GetBytes("Tired of lying in the sunshine, staying home to watch the rain,"));
                await Task.Delay(100);
                this.classicSerialPort.Write(Encoding.ASCII.GetBytes("you are young and life is long and there is time to kill today."));
                await Task.Delay(100);
                this.classicSerialPort.Write(Encoding.ASCII.GetBytes("And then one day you find ten years have got behind you,"));
                await Task.Delay(100);
                this.classicSerialPort.Write(Encoding.ASCII.GetBytes("No one told you when to run, you missed the starting gun."));
                await Task.Delay(100);
            });

            //weak ass Hack to wait for them all to process
            Thread.Sleep(500);

            //tear-down
            this.classicSerialPort.DataReceived -= ProcessData;

            // anonymous method declaration so we can unwire later.
            async void ProcessData(object sender, SerialDataReceivedEventArgs e)
            {
                Console.WriteLine("Serial Data Received");
                byte[] buffer = new byte[512];
                while (true) {
                    int readCount = await classicSerialPort.Read(buffer, 0, 512);
                    Console.Write(ParseToString(buffer, readCount));
                    // if we got all the data, break the while loop, otherwise, keep going.
                    if (readCount < 512) { break; }
                }
                Console.Write("\n");
            }

        }



        /// <summary>
        /// C# compiler doesn't allow Span<T> in async methods, so can't do this
        /// inline.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        protected string ParseToString(byte[] buffer, int length)
        {
            Span<byte> actualData = buffer.AsSpan<byte>().Slice(0, length);
            return Encoding.ASCII.GetString(actualData);
        }

        void AsyncReadWaitTest()
        {

        }
    }
}