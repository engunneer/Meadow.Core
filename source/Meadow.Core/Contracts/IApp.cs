﻿using System;
namespace Meadow
{
    /// <summary>
    /// Contract for Meadow applications. Provides a way for the Meadow OS to 
    /// communicate with Meadow applications when system events are happening.
    /// </summary>
    public interface IApp
    {
        /// <summary>
        /// Called the first time the application is started.
        /// TODO: Is this necessary? Why not just use the ctor?
        /// </summary>
        void Run();

        /// <summary>
        /// Called when the application is going to be sleep.
        /// </summary>
        void WillSleep();

        /// <summary>
        /// Called when the application wakes up from sleep.
        /// </summary>
        void OnWake();

        /// <summary>
        /// Called in case the OS needs to restart the app. Will have limited 
        /// processing time.
        /// </summary>
        void WillReset();
    }
}
