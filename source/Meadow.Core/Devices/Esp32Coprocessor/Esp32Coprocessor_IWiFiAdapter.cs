﻿using System;
using System.Collections.ObjectModel;
using System.Net;
using System.Threading.Tasks;
using Meadow.Devices.Esp32.MessagePayloads;
using Meadow.Gateways;
using Meadow.Gateway.WiFi;
using Meadow.Gateways.Exceptions;

namespace Meadow.Devices
{
    /// <summary>
	/// This file holds the WiFi specifi methods, properties etc for the IWiFiAdapter interface.
	/// </summary>
    public partial class Esp32Coprocessor : IWiFiAdapter
    {
        #region Events

        /// <summary>
        /// Raised when the device connects to WiFi.
        /// </summary>
        public event EventHandler WiFiConnected = delegate { };

        /// <summary>
        /// Raised when the device disconnects from WiFi.
        /// </summary>
        public event EventHandler WiFiDisconnected = delegate { };

        /// <summary>
        /// Raised when the WiFi interface starts.
        /// </summary>
        public event EventHandler WiFiInterfaceStarted = delegate { };

        /// <summary>
        /// Raised when the WiFi interface stops.
        /// </summary>
        public event EventHandler WiFiInterfaceStopped = delegate { };

        #endregion Events


        #region Constants

        /// <summary>
        /// Default delay (in milliseconds) between WiFi network scans <see cref="ScanFrequency"/>.
        /// </summary>
        public const ushort DEFAULT_SCAN_FREQUENCY = 5000;

        /// <summary>
        /// Minimum delay (in milliseconds) that can be used for the <see cref="ScanFrequency"/>.
        /// </summary>
        public const ushort MINIMUM_SCAN_FREQUENCY = 1000;

        /// <summary>
        /// Maximum delay (in milliseconds) that can be used for the <see cref="ScanFrequency"/>.
        /// </summary>
        public const ushort MAXIMUM_SCAN_FREQUENCY = 60000;

        #endregion Constants

        #region Properties

        /// <summary>
        /// IP Address of the network adapter.
        /// </summary>
        public IPAddress IpAddress { get; private set; }

        /// <summary>
        /// Subnet mask of the adapter.
        /// </summary>
        public IPAddress SubnetMask { get; private set; }

        /// <summary>
        /// Default gateway for the adapter.
        /// </summary>
        public IPAddress Gateway { get; private set; }

        /// <summary>
        /// Record if the WiFi ESP32 is connected to an access point.
        /// </summary>
        public bool IsConnected { get; private set; }

        /// <summary>
        /// Current onboard antenna in use.
        /// </summary>
        public AntennaType Antenna
        {
            get
            {
                if (GetConfiguration() != StatusCodes.CompletedOk)
                {
                    throw new InvalidNetworkOperationException("Cannot retrieve ESP32 configuration.");
                }
                AntennaType result;
                if (_config.Value.Antenna == (byte) AntennaTypes.OnBoard)
                {
                    result = AntennaType.OnBoard;
                }
                else
                {
                    result = AntennaType.External;
                }
                return (result);
            }
        }

        /// <summary>
        /// Should the system automatically get the time when the board is connected to an access point?
        /// </summary>
        public bool GetNetworkTimeAtStartup
        {
            get
            {
                if (GetConfiguration() != StatusCodes.CompletedOk)
                {
                    throw new InvalidNetworkOperationException("Cannot retrieve ESP32 configuration.");
                }
                return (_config.Value.GetTimeAtStartup == 1);
            }
            //set { SetProperty(ConfigurationItems.GetTimeAtStartup, value); }
        }

        /// <summary>
        /// Name of the NTP server to use for time retrieval.
        /// </summary>
        public string NtpServer
        {
            get
            {
                if (GetConfiguration() != StatusCodes.CompletedOk)
                {
                    throw new InvalidNetworkOperationException("Cannot retrieve ESP32 configuration.");
                }
                return (_config.Value.NtpServer);
            }
            //set { SetProperty(ConfigurationItems.NtpServer, value); }
        }

        /// <summary>
        /// Get the device name.
        /// </summary>
        /// <remarks>
        /// This value should be changed through the meadow.cfg file.
        /// </remarks>
        public string DeviceName
        {
            get
            {
                if (GetConfiguration() != StatusCodes.CompletedOk)
                {
                    throw new InvalidNetworkOperationException("Cannot retrieve ESP32 configuration.");
                }
                return (_config.Value.DeviceName);
            }
        }

        /// <summary>
        /// MAC address as used by the ESP32 when acting as a client.
        /// </summary>
        public byte[] MacAddress
        {
            get
            {
                if (GetConfiguration() != StatusCodes.CompletedOk)
                {
                    throw new InvalidNetworkOperationException("Cannot retrieve ESP32 configuration.");
                }
                return (_config.Value.BoardMacAddress);
            }

        }

        /// <summary>
        /// MAC address as used by the ESP32 when acting as an access point.
        /// </summary>
        public byte[] ApMacAddress
        {
            get
            {
                if (GetConfiguration() != StatusCodes.CompletedOk)
                {
                    throw new InvalidNetworkOperationException("Cannot retrieve ESP32 configuration.");
                }
                return (_config.Value.SoftApMacAddress);
            }

        }

        /// <summary>
        /// Automatically start the network interface when the board reboots?
        /// </summary>
        /// <remarks>
        /// This will automatically connect to any preconfigured access points if they are available.
        /// </remarks>
        public bool AutomaticallyStartNetwork
        {
            get
            {
                if (GetConfiguration() != StatusCodes.CompletedOk)
                {
                    throw new InvalidNetworkOperationException("Cannot retrieve ESP32 configuration.");
                }
                return (_config.Value.AutomaticallyStartNetwork == 1);
            }
            //set { SetProperty(ConfigurationItems.NtpServer, value); }
        }

        /// <summary>
        /// Automatically try to reconnect to an access point if there is a problem / disconnection?
        /// </summary>
        public bool AutomaticallyReconnect
        {
            get
            {
                if (GetConfiguration() != StatusCodes.CompletedOk)
                {
                    throw new InvalidNetworkOperationException("Cannot retrieve ESP32 configuration.");
                }
                return (_config.Value.AutomaticallyReconnect == 1);
            }
            //set { SetProperty(ConfigurationItems.NtpServer, value); }
        }

        /// <summary>
        /// Default access point to try to connect to if the network interface is started and the board
        /// is configured to automatically reconnect.
        /// </summary>
        public string DefaultAcessPoint
        {
            get
            {
                if (GetConfiguration() != StatusCodes.CompletedOk)
                {
                    throw new InvalidNetworkOperationException("Cannot retrieve ESP32 configuration.");
                }
                return (_config.Value.DefaultAccessPoint);
            }
            //set { SetProperty(ConfigurationItems.NtpServer, value); }
        }

        /// <summary>
        /// Does the access point the WiFi adapter is currently connected to have internet access?
        /// </summary>
        public bool HasInternetAccess { get; protected set; }

        #endregion Properties

        #region Methods

        /// <summary>
        /// Delay (in milliseconds) between network scans.
        /// </summary>
        /// <remarks>
        /// This will default to the <see cref="DEFAULT_SCAN_FREQUENCY"/> value.
        ///
        /// The ScanFrequency should be between <see cref="MINIMUM_SCAN_FREQUENCY"/> and
        /// <see cref="MAXIMUM_SCAN_FREQUENCY"/> (inclusive).
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">Exception is thrown if value is less than <see cref="MINIMUM_SCAN_FREQUENCY"/> or greater than <see cref="MAXIMUM_SCAN_FREQUENCY"/>.</exception>
        private ushort _scanFrequency = DEFAULT_SCAN_FREQUENCY;
        public ushort ScanFrequency
        {
            get { return (_scanFrequency); }
            set
            {
                if ((value < MINIMUM_SCAN_FREQUENCY) || (value > MAXIMUM_SCAN_FREQUENCY))
                {
                    throw new ArgumentOutOfRangeException($"{nameof(ScanFrequency)} should be between {MINIMUM_SCAN_FREQUENCY} and {MAXIMUM_SCAN_FREQUENCY} (inclusive).");
                }
                _scanFrequency = value;
            }
        }

        /// <summary>
        /// Use the event data to work out which event to invoke and create any event args that will be consumed.
        /// </summary>
        /// <param name="eventId">Event ID.</param>
        /// <param name="statusCode">Status of the event.</param>
        /// <param name="payload">Optional payload containing data specific to the result of the event.</param>
        protected void InvokeEvent(WiFiFunction eventId, StatusCodes statusCode, byte[] payload)
        {
            switch (eventId)
            {
                case WiFiFunction.ConnectEvent:
                    RaiseWiFiConnected(statusCode, payload);
                    break;
                case WiFiFunction.DisconnectEvent:
                    RaiseWiFiDisconnected(statusCode, payload);
                    break;
                case WiFiFunction.StartInterfaceEvent:
                    RaiseWiFiInterfaceStarted(statusCode, payload);
                    break;
                case WiFiFunction.StopInterfaceEvent:
                    RaiseWiFiInterfaceStopped(statusCode, payload);
                    break;
                default:
                    throw new NotImplementedException($"WiFi event not implemented ({eventId}).");
            }
        }

        /// <summary>
        /// Clear the IP address, subnet mask and gateway details.
        /// </summary>
        private void ClearIpDetails()
        {
            byte[] addressBytes = new byte[4];
            Array.Clear(addressBytes, 0, addressBytes.Length);
            IpAddress = new IPAddress(addressBytes);
            SubnetMask = new IPAddress(addressBytes);
            Gateway = new IPAddress(addressBytes);
        }

        // TODO: this really should probably not return the networks, but rather
        // populate the collection that it used to do.
        /// <summary>
        /// Scan for networks.
        /// </summary>
        /// <remarks>
        /// The network must be started before this method can be called.
        /// </remarks>
        public ObservableCollection<WifiNetwork> Scan()
        {
            var networks = new ObservableCollection<WifiNetwork>();
            byte[] resultBuffer = new byte[MAXIMUM_SPI_BUFFER_LENGTH];
            StatusCodes result = SendCommand((byte) Esp32Interfaces.WiFi, (UInt32) WiFiFunction.GetAccessPoints, true, resultBuffer);
            if (result == StatusCodes.CompletedOk)
            {
                var accessPointList = Encoders.ExtractAccessPointList(resultBuffer, 0);
                var accessPoints = new AccessPoint[accessPointList.NumberOfAccessPoints];

                if (accessPointList.NumberOfAccessPoints > 0)
                {
                    int accessPointOffset = 0;
                    for (int count = 0; count < accessPointList.NumberOfAccessPoints; count++)
                    {
                        var accessPoint = Encoders.ExtractAccessPoint(accessPointList.AccessPoints, accessPointOffset);
                        accessPointOffset += Encoders.EncodedAccessPointBufferSize(accessPoint);
                        string bssid = "";
                        for (int index = 0; index < accessPoint.Bssid.Length; index++)
                        {
                            bssid += accessPoint.Bssid[index].ToString("x2");
                            if (index != accessPoint.Bssid.Length - 1)
                            {
                                bssid += ":";
                            }
                        }
                        var network = new WifiNetwork(accessPoint.Ssid, bssid, NetworkType.Infrastructure, PhyType.Unknown,
                            new NetworkSecuritySettings((NetworkAuthenticationType)accessPoint.AuthenticationMode, NetworkEncryptionType.Unknown),
                            accessPoint.PrimaryChannel, (NetworkProtocol)accessPoint.Protocols, accessPoint.Rssi);
                        networks.Add(network);
                    }
                }
            }
            else
            {
                Console.WriteLine($"Error getting access points: {result}");
            }
            return (networks);
        }

        /// <summary>
        /// Connect to a WiFi network.
        /// </summary>
        /// <param name="ssid">SSID of the network to connect to</param>
        /// <param name="password">Password for the WiFi access point.</param>
        /// <param name="reconnection">Determine if the adapter should automatically attempt to reconnect (see <see cref="ReconnectionType"/>) to the access point if it becomes disconnected for any reason.</param>
        /// <returns></returns>
        //TODO: we should probably be using some sort of password credential and secure storage see: https://docs.microsoft.com/en-us/uwp/api/windows.security.credentials.passwordcredential
        public async Task<ConnectionResult> Connect(string ssid, string password, ReconnectionType reconnection = ReconnectionType.Automatic)
        {
            var t = await Task.Run<ConnectionResult>(() => {
                ConnectionResult connectionResult;
                if (ConnectToAccessPoint(ssid, password, reconnection))
                {
                    HasInternetAccess = true;
                    connectionResult = new ConnectionResult(ConnectionStatus.Success);
                }
                else
                {
                    HasInternetAccess = false;
                    connectionResult = new ConnectionResult(ConnectionStatus.UnspecifiedFailure);
                }
                return connectionResult;
            });
            return t;
        }

        /// <summary>
        /// Disconnect from the current network.
        /// </summary>
        public void Disconect()
        {
        }

        /// <summary>
        /// Start the network interface on the WiFi adapter.
        /// </summary>
        /// <remarks>
        /// This method starts the network interface hardware.  The result of this action depends upon the
        /// settings stored in the WiFi adapter memory.
        ///
        /// No Stored Configuration
        /// If no settings are stored in the adapter then the hardware will simply start.  IP addresses
        /// will not be obtained in this mode.
        ///
        /// In this case, the return result indicates if the hardware started successfully.
        ///
        /// Stored Configuration Present NOTE NOT IMPLEMENTED IN THIS RELEASE
        /// If a default access point (and optional password) are stored in the adapter then the network
        /// interface and the system is set to connect at startup then the system will then attempt to
        /// connect to the specified access point.
        ///
        /// In this case, the return result indicates if the interface was started successfully and a
        /// connection to the access point was made.
        /// </remarks>
        /// <returns>true if the adapter was started successfully, false if there was an error.</returns>
        public bool StartNetwork()
        {
            StatusCodes result = SendCommand((byte) Esp32Interfaces.WiFi, (UInt32) WiFiFunction.StartNetwork, true, null);
            return (result == StatusCodes.CompletedOk);
        }

        /// <summary>
        /// Request the ESP32 to connect to the specified network.
        /// </summary>
        /// <param name="ssid">Name of the network to connect to.</param>
        /// <param name="password">Password for the network.</param>
        /// <param name="reconnection">Should the adapter reconnect automatically?</param>
        /// <exception cref="ArgumentNullException">Thrown if the ssid is null or empty or the password is null.</exception>
        /// <returns>true if the connection was successfully made.</returns>
        private bool ConnectToAccessPoint(string ssid, string password, ReconnectionType reconnection)
        {
            if (string.IsNullOrEmpty(ssid))
            {
                throw new ArgumentNullException("Invalid SSID.");
            }
            if (password == null)
            {
                throw new ArgumentNullException($"{nameof(password)} cannot be null.");
            }

            WiFiCredentials request = new WiFiCredentials()
            {
                NetworkName = ssid,
                Password = password
            };
            byte[] encodedPayload = Encoders.EncodeWiFiCredentials(request);
            byte[] resultBuffer = new byte[MAXIMUM_SPI_BUFFER_LENGTH];

            // TODO: should be async and awaited
            StatusCodes result = SendCommand((byte) Esp32Interfaces.WiFi, (UInt32) WiFiFunction.ConnectToAccessPoint, true, encodedPayload, resultBuffer);

            if ((result == StatusCodes.CompletedOk))
            {
                byte[] addressBytes = new byte[4];
                Array.Copy(resultBuffer, addressBytes, addressBytes.Length);
                IpAddress = new IPAddress(addressBytes);
                Array.Copy(resultBuffer, 4, addressBytes, 0, addressBytes.Length);
                SubnetMask = new IPAddress(addressBytes);
                Array.Copy(resultBuffer, 8, addressBytes, 0, addressBytes.Length);
                Gateway = new IPAddress(addressBytes);
                IsConnected = true;
            }
            else
            {
                ClearIpDetails();
                IsConnected = false;
                if (result == StatusCodes.CoprocessorNotResponding)
                {
                    throw new InvalidNetworkOperationException("ESP32 coprocessor is not responding.");
                }
            }
            return (IsConnected);
        }

        /// <summary>
        /// Change the current WiFi antenna.
        /// </summary>
        /// <remarks>
        /// Allows the application to change the current antenna used by the WiFi adapter.  This
        /// can be made to persist between reboots / power cycles by setting the persist option
        /// to true.
        /// </remarks>
        /// <param name="antenna">New antenna to use.</param>
        /// <param name="persist">Make the antenna change persistent.</param>
        public void SetAntenna(AntennaType antenna, bool persist = true)
        {
            //
            //  TODO: Work out what checks we need to do here.
            //
            SetAntennaRequest request = new SetAntennaRequest();
            if (persist)
            {
                request.Persist = 1;
            }
            else
            {
                request.Persist = 0;
            }
            if (antenna == AntennaType.OnBoard)
            {
                request.Antenna = (byte) AntennaTypes.OnBoard;
            }
            else
            {
                request.Antenna = (byte) AntennaTypes.External;
            }
            byte[] encodedPayload = Encoders.EncodeSetAntennaRequest(request);
            byte[] encodedResult = new byte[4000];
            StatusCodes result = SendCommand((byte) Esp32Interfaces.WiFi, (UInt32) WiFiFunction.SetAntenna, true, encodedPayload, encodedResult);
            if (result != StatusCodes.CompletedOk)
            {
                throw new Exception("Failed to change the antenna in use.");
            }
        }

        #endregion Methods

        #region Event raising methods

        /// <summary>
        /// Process the ConnectionCompleted event extracing any event data from the
        /// payload and create an EventArg object if necessary
        /// </summary>
        /// <param name="statusCode">Status code for the WiFi connection</param>
        /// <param name="payload">Event data encoded in the payload.</param>
        protected void RaiseWiFiConnected(StatusCodes statusCode, byte[] payload)
        {
            EventArgs e = EventArgs.Empty;
            WiFiConnected?.Invoke(this, e);
        }

        /// <summary>
        /// Process the Disconnected event extracing any event data from the
        /// payload and create an EventArg object if necessary
        /// </summary>
        /// <param name="statusCode">Status code for the WiFi disconnection request.</param>
        /// <param name="payload">Event data encoded in the payload.</param>
        protected void RaiseWiFiDisconnected(StatusCodes statusCode, byte[] payload)
        {
            EventArgs e = EventArgs.Empty;
            WiFiDisconnected?.Invoke(this, e);
        }

        /// <summary>
        /// Process the InterfaceStarted event extracing any event data from the
        /// payload and create an EventArg object if necessary
        /// </summary>
        /// <param name="statusCode">Status code for the WiFi interface start event (should be CompletedOK).</param>
        /// <param name="payload">Event data encoded in the payload.</param>
        protected void RaiseWiFiInterfaceStarted(StatusCodes statusCode, byte[] payload)
        {
            EventArgs e = EventArgs.Empty;
            WiFiInterfaceStarted?.Invoke(this, e);
        }

        /// <summary>
        /// Process the InterfaceStopped event extracing any event data from the
        /// payload and create an EventArg object if necessary
        /// </summary>
        /// <param name="statusCode">Status code for the WiFi interface stop event (should be CompletedOK).</param>
        /// <param name="payload">Event data encoded in the payload.</param>
        protected void RaiseWiFiInterfaceStopped(StatusCodes statusCode, byte[] payload)
        {
            EventArgs e = EventArgs.Empty;
            WiFiInterfaceStopped?.Invoke(this, e);
        }

        #endregion Event raising methods
    }
}
