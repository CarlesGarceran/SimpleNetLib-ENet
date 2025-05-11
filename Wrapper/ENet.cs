/*
 *  Managed C# wrapper for an extended version of ENet
 *  Copyright (c) 2013 James Bellinger
 *  Copyright (c) 2016 Nate Shoffner
 *  Copyright (c) 2018 Stanislav Denisov
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace SimpleNetLib_ENet.Wrapper
{
    [Flags]
    public enum PacketFlags
    {
        None = 0,
        Reliable = 1 << 0,
        Unsequenced = 1 << 1,
        NoAllocate = 1 << 2,
        UnreliableFragmented = 1 << 3,
        Instant = 1 << 4,
        Unthrottled = 1 << 5,
        Sent = 1 << 8
    }

    public enum EventType
    {
        None = 0,
        Connect = 1,
        Disconnect = 2,
        Receive = 3,
        Timeout = 4
    }

    public enum PeerState
    {
        Uninitialized = -1,
        Disconnected = 0,
        Connecting = 1,
        AcknowledgingConnect = 2,
        ConnectionPending = 3,
        ConnectionSucceeded = 4,
        Connected = 5,
        DisconnectLater = 6,
        Disconnecting = 7,
        AcknowledgingDisconnect = 8,
        Zombie = 9
    }

    [StructLayout(LayoutKind.Explicit, Size = 18)]
    internal struct ENetAddress
    {
        [FieldOffset(16)]
        public ushort port;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ENetEvent
    {
        public EventType type;
        public nint peer;
        public byte channelID;
        public uint data;
        public nint packet;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ENetCallbacks
    {
        public AllocCallback malloc;
        public FreeCallback free;
        public NoMemoryCallback noMemory;
    }

    public delegate nint AllocCallback(nint size);
    public delegate void FreeCallback(nint memory);
    public delegate void NoMemoryCallback();
    public delegate void PacketFreeCallback(Packet packet);
    public delegate int InterceptCallback(ref Event @event, ref Address address, nint receivedData, int receivedDataLength);
    public delegate ulong ChecksumCallback(nint buffers, int bufferCount);

    internal static class ArrayPool
    {
        [ThreadStatic]
        private static byte[] byteBuffer;
        [ThreadStatic]
        private static nint[] pointerBuffer;

        public static byte[] GetByteBuffer()
        {
            if (byteBuffer == null)
                byteBuffer = new byte[64];

            return byteBuffer;
        }

        public static nint[] GetPointerBuffer()
        {
            if (pointerBuffer == null)
                pointerBuffer = new nint[Library.maxPeers];

            return pointerBuffer;
        }
    }

    public struct Address
    {
        private ENetAddress nativeAddress;

        internal ENetAddress NativeData
        {
            get
            {
                return nativeAddress;
            }

            set
            {
                nativeAddress = value;
            }
        }

        internal Address(ENetAddress address)
        {
            nativeAddress = address;
        }

        public ushort Port
        {
            get
            {
                return nativeAddress.port;
            }

            set
            {
                nativeAddress.port = value;
            }
        }

        public string GetIP()
        {
            StringBuilder ip = new StringBuilder(1025);

            if (Native.enet_address_get_ip(ref nativeAddress, ip, ip.Capacity) != 0)
                return string.Empty;

            return ip.ToString();
        }

        public bool SetIP(string ip)
        {
            if (ip == null)
                throw new ArgumentNullException("ip");

            return Native.enet_address_set_ip(ref nativeAddress, ip) == 0;
        }

        public string GetHost()
        {
            StringBuilder hostName = new StringBuilder(1025);

            if (Native.enet_address_get_hostname(ref nativeAddress, hostName, hostName.Capacity) != 0)
                return string.Empty;

            return hostName.ToString();
        }

        public bool SetHost(string hostName)
        {
            if (hostName == null)
                throw new ArgumentNullException("hostName");

            return Native.enet_address_set_hostname(ref nativeAddress, hostName) == 0;
        }
    }

    public struct Event
    {
        private ENetEvent nativeEvent;

        internal ENetEvent NativeData
        {
            get
            {
                return nativeEvent;
            }

            set
            {
                nativeEvent = value;
            }
        }

        internal Event(ENetEvent @event)
        {
            nativeEvent = @event;
        }

        public EventType Type
        {
            get
            {
                return nativeEvent.type;
            }
        }

        public Peer Peer
        {
            get
            {
                return new Peer(nativeEvent.peer);
            }
        }

        public byte ChannelID
        {
            get
            {
                return nativeEvent.channelID;
            }
        }

        public uint Data
        {
            get
            {
                return nativeEvent.data;
            }
        }

        public Packet Packet
        {
            get
            {
                return new Packet(nativeEvent.packet);
            }
        }
    }

    public class Callbacks
    {
        private ENetCallbacks nativeCallbacks;

        internal ENetCallbacks NativeData
        {
            get
            {
                return nativeCallbacks;
            }

            set
            {
                nativeCallbacks = value;
            }
        }

        public Callbacks(AllocCallback allocCallback, FreeCallback freeCallback, NoMemoryCallback noMemoryCallback)
        {
            nativeCallbacks.malloc = allocCallback;
            nativeCallbacks.free = freeCallback;
            nativeCallbacks.noMemory = noMemoryCallback;
        }
    }

    public struct Packet : IDisposable
    {
        private nint nativePacket;

        internal nint NativeData
        {
            get
            {
                return nativePacket;
            }

            set
            {
                nativePacket = value;
            }
        }

        internal Packet(nint packet)
        {
            nativePacket = packet;
        }

        public void Dispose()
        {
            if (nativePacket != nint.Zero)
            {
                Native.enet_packet_dispose(nativePacket);
                nativePacket = nint.Zero;
            }
        }

        public bool IsSet
        {
            get
            {
                return nativePacket != nint.Zero;
            }
        }

        public nint Data
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_packet_get_data(nativePacket);
            }
        }

        public nint UserData
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_packet_get_user_data(nativePacket);
            }

            set
            {
                ThrowIfNotCreated();

                Native.enet_packet_set_user_data(nativePacket, value);
            }
        }

        public int Length
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_packet_get_length(nativePacket);
            }
        }

        public bool HasReferences
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_packet_check_references(nativePacket) != 0;
            }
        }

        internal void ThrowIfNotCreated()
        {
            if (nativePacket == nint.Zero)
                throw new InvalidOperationException("Packet not created");
        }

        public void SetFreeCallback(nint callback)
        {
            ThrowIfNotCreated();

            Native.enet_packet_set_free_callback(nativePacket, callback);
        }

        public void SetFreeCallback(PacketFreeCallback callback)
        {
            ThrowIfNotCreated();

            Native.enet_packet_set_free_callback(nativePacket, Marshal.GetFunctionPointerForDelegate(callback));
        }

        public void Create(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            Create(data, data.Length);
        }

        public void Create(byte[] data, int length)
        {
            Create(data, length, PacketFlags.None);
        }

        public void Create(byte[] data, PacketFlags flags)
        {
            Create(data, data.Length, flags);
        }

        public void Create(byte[] data, int length, PacketFlags flags)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            if (length < 0 || length > data.Length)
                throw new ArgumentOutOfRangeException("length");

            nativePacket = Native.enet_packet_create(data, length, flags);
        }

        public void Create(nint data, int length, PacketFlags flags)
        {
            if (data == nint.Zero)
                throw new ArgumentNullException("data");

            if (length < 0)
                throw new ArgumentOutOfRangeException("length");

            nativePacket = Native.enet_packet_create(data, length, flags);
        }

        public void Create(byte[] data, int offset, int length, PacketFlags flags)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            if (offset < 0)
                throw new ArgumentOutOfRangeException("offset");

            if (length < 0 || length > data.Length)
                throw new ArgumentOutOfRangeException("length");

            nativePacket = Native.enet_packet_create_offset(data, length, offset, flags);
        }

        public void Create(nint data, int offset, int length, PacketFlags flags)
        {
            if (data == nint.Zero)
                throw new ArgumentNullException("data");

            if (offset < 0)
                throw new ArgumentOutOfRangeException("offset");

            if (length < 0)
                throw new ArgumentOutOfRangeException("length");

            nativePacket = Native.enet_packet_create_offset(data, length, offset, flags);
        }

        public void CopyTo(byte[] destination)
        {
            if (destination == null)
                throw new ArgumentNullException("destination");

            Marshal.Copy(Data, destination, 0, Length);
        }
    }

    public class Host : IDisposable
    {
        private nint nativeHost;

        internal nint NativeData
        {
            get
            {
                return nativeHost;
            }

            set
            {
                nativeHost = value;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (nativeHost != nint.Zero)
            {
                Native.enet_host_destroy(nativeHost);
                nativeHost = nint.Zero;
            }
        }

        ~Host()
        {
            Dispose(false);
        }

        public bool IsSet
        {
            get
            {
                return nativeHost != nint.Zero;
            }
        }

        public uint PeersCount
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_host_get_peers_count(nativeHost);
            }
        }

        public uint PacketsSent
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_host_get_packets_sent(nativeHost);
            }
        }

        public uint PacketsReceived
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_host_get_packets_received(nativeHost);
            }
        }

        public uint BytesSent
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_host_get_bytes_sent(nativeHost);
            }
        }

        public uint BytesReceived
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_host_get_bytes_received(nativeHost);
            }
        }

        internal void ThrowIfNotCreated()
        {
            if (nativeHost == nint.Zero)
                throw new InvalidOperationException("Host not created");
        }

        private static void ThrowIfChannelsExceeded(int channelLimit)
        {
            if (channelLimit < 0 || channelLimit > Library.maxChannelCount)
                throw new ArgumentOutOfRangeException("channelLimit");
        }

        public void Create()
        {
            Create(null, 1, 0);
        }

        public void Create(int bufferSize)
        {
            Create(null, 1, 0, 0, 0, bufferSize);
        }

        public void Create(Address? address, int peerLimit)
        {
            Create(address, peerLimit, 0);
        }

        public void Create(Address? address, int peerLimit, int channelLimit)
        {
            Create(address, peerLimit, channelLimit, 0, 0, 0);
        }

        public void Create(int peerLimit, int channelLimit)
        {
            Create(null, peerLimit, channelLimit, 0, 0, 0);
        }

        public void Create(int peerLimit, int channelLimit, uint incomingBandwidth, uint outgoingBandwidth)
        {
            Create(null, peerLimit, channelLimit, incomingBandwidth, outgoingBandwidth, 0);
        }

        public void Create(Address? address, int peerLimit, int channelLimit, uint incomingBandwidth, uint outgoingBandwidth)
        {
            Create(address, peerLimit, channelLimit, incomingBandwidth, outgoingBandwidth, 0);
        }

        public void Create(Address? address, int peerLimit, int channelLimit, uint incomingBandwidth, uint outgoingBandwidth, int bufferSize)
        {
            if (nativeHost != nint.Zero)
                throw new InvalidOperationException("Host already created");

            if (peerLimit < 0 || peerLimit > Library.maxPeers)
                throw new ArgumentOutOfRangeException("peerLimit");

            ThrowIfChannelsExceeded(channelLimit);

            if (address != null)
            {
                var nativeAddress = address.Value.NativeData;

                nativeHost = Native.enet_host_create(ref nativeAddress, peerLimit, channelLimit, incomingBandwidth, outgoingBandwidth, bufferSize);
            }
            else
            {
                nativeHost = Native.enet_host_create(nint.Zero, peerLimit, channelLimit, incomingBandwidth, outgoingBandwidth, bufferSize);
            }

            if (nativeHost == nint.Zero)
                throw new InvalidOperationException("Host creation call failed");
        }

        public void PreventConnections(bool state)
        {
            ThrowIfNotCreated();

            Native.enet_host_prevent_connections(nativeHost, (byte)(state ? 1 : 0));
        }

        public void Broadcast(byte channelID, ref Packet packet)
        {
            ThrowIfNotCreated();

            packet.ThrowIfNotCreated();
            Native.enet_host_broadcast(nativeHost, channelID, packet.NativeData);
            packet.NativeData = nint.Zero;
        }

        public void Broadcast(byte channelID, ref Packet packet, Peer excludedPeer)
        {
            ThrowIfNotCreated();

            packet.ThrowIfNotCreated();
            Native.enet_host_broadcast_exclude(nativeHost, channelID, packet.NativeData, excludedPeer.NativeData);
            packet.NativeData = nint.Zero;
        }

        public void Broadcast(byte channelID, ref Packet packet, Peer[] peers)
        {
            if (peers == null)
                throw new ArgumentNullException("peers");

            ThrowIfNotCreated();

            packet.ThrowIfNotCreated();

            if (peers.Length > 0)
            {
                nint[] nativePeers = ArrayPool.GetPointerBuffer();
                int nativeCount = 0;

                for (int i = 0; i < peers.Length; i++)
                {
                    if (peers[i].NativeData != nint.Zero)
                    {
                        nativePeers[nativeCount] = peers[i].NativeData;
                        nativeCount++;
                    }
                }

                Native.enet_host_broadcast_selective(nativeHost, channelID, packet.NativeData, nativePeers, nativeCount);
                packet.NativeData = nint.Zero;
            }
            else
            {
                packet.Dispose();

                throw new ArgumentOutOfRangeException("Peers array can't be empty");
            }
        }

        public int CheckEvents(out Event @event)
        {
            ThrowIfNotCreated();

            ENetEvent nativeEvent;

            var result = Native.enet_host_check_events(nativeHost, out nativeEvent);

            if (result <= 0)
            {
                @event = default;

                return result;
            }

            @event = new Event(nativeEvent);

            return result;
        }

        public Peer Connect(Address address)
        {
            return Connect(address, 0, 0);
        }

        public Peer Connect(Address address, int channelLimit)
        {
            return Connect(address, channelLimit, 0);
        }

        public Peer Connect(Address address, int channelLimit, uint data)
        {
            ThrowIfNotCreated();
            ThrowIfChannelsExceeded(channelLimit);

            var nativeAddress = address.NativeData;
            var peer = new Peer(Native.enet_host_connect(nativeHost, ref nativeAddress, channelLimit, data));

            if (peer.NativeData == nint.Zero)
                throw new InvalidOperationException("Host connect call failed");

            return peer;
        }

        public int Service(int timeout, out Event @event)
        {
            if (timeout < 0)
                throw new ArgumentOutOfRangeException("timeout");

            ThrowIfNotCreated();

            ENetEvent nativeEvent;

            var result = Native.enet_host_service(nativeHost, out nativeEvent, (uint)timeout);

            if (result <= 0)
            {
                @event = default;

                return result;
            }

            @event = new Event(nativeEvent);

            return result;
        }

        public void SetBandwidthLimit(uint incomingBandwidth, uint outgoingBandwidth)
        {
            ThrowIfNotCreated();

            Native.enet_host_bandwidth_limit(nativeHost, incomingBandwidth, outgoingBandwidth);
        }

        public void SetChannelLimit(int channelLimit)
        {
            ThrowIfNotCreated();
            ThrowIfChannelsExceeded(channelLimit);

            Native.enet_host_channel_limit(nativeHost, channelLimit);
        }

        public void SetMaxDuplicatePeers(ushort number)
        {
            ThrowIfNotCreated();

            Native.enet_host_set_max_duplicate_peers(nativeHost, number);
        }

        public void SetInterceptCallback(nint callback)
        {
            ThrowIfNotCreated();

            Native.enet_host_set_intercept_callback(nativeHost, callback);
        }

        public void SetInterceptCallback(InterceptCallback callback)
        {
            ThrowIfNotCreated();

            Native.enet_host_set_intercept_callback(nativeHost, Marshal.GetFunctionPointerForDelegate(callback));
        }

        public void SetChecksumCallback(nint callback)
        {
            ThrowIfNotCreated();

            Native.enet_host_set_checksum_callback(nativeHost, callback);
        }

        public void SetChecksumCallback(ChecksumCallback callback)
        {
            ThrowIfNotCreated();

            Native.enet_host_set_checksum_callback(nativeHost, Marshal.GetFunctionPointerForDelegate(callback));
        }

        public void Flush()
        {
            ThrowIfNotCreated();

            Native.enet_host_flush(nativeHost);
        }
    }

    public struct Peer
    {
        private nint nativePeer;
        private uint nativeID;

        internal nint NativeData
        {
            get
            {
                return nativePeer;
            }

            set
            {
                nativePeer = value;
            }
        }

        internal Peer(nint peer)
        {
            nativePeer = peer;
            nativeID = nativePeer != nint.Zero ? Native.enet_peer_get_id(nativePeer) : 0;
        }

        public bool IsSet
        {
            get
            {
                return nativePeer != nint.Zero;
            }
        }

        public uint ID
        {
            get
            {
                return nativeID;
            }
        }

        public string IP
        {
            get
            {
                ThrowIfNotCreated();

                byte[] ip = ArrayPool.GetByteBuffer();

                if (Native.enet_peer_get_ip(nativePeer, ip, ip.Length) == 0)
                    return Encoding.ASCII.GetString(ip, 0, ip.StringLength());
                else
                    return string.Empty;
            }
        }

        public ushort Port
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_port(nativePeer);
            }
        }

        public uint MTU
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_mtu(nativePeer);
            }
        }

        public PeerState State
        {
            get
            {
                return nativePeer == nint.Zero ? PeerState.Uninitialized : Native.enet_peer_get_state(nativePeer);
            }
        }

        public uint RoundTripTime
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_rtt(nativePeer);
            }
        }

        public uint LastRoundTripTime
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_last_rtt(nativePeer);
            }
        }

        public uint LastSendTime
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_lastsendtime(nativePeer);
            }
        }

        public uint LastReceiveTime
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_lastreceivetime(nativePeer);
            }
        }

        public ulong PacketsSent
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_packets_sent(nativePeer);
            }
        }

        public ulong PacketsLost
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_packets_lost(nativePeer);
            }
        }

        public float PacketsThrottle
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_packets_throttle(nativePeer);
            }
        }

        public ulong BytesSent
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_bytes_sent(nativePeer);
            }
        }

        public ulong BytesReceived
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_bytes_received(nativePeer);
            }
        }

        public nint Data
        {
            get
            {
                ThrowIfNotCreated();

                return Native.enet_peer_get_data(nativePeer);
            }

            set
            {
                ThrowIfNotCreated();

                Native.enet_peer_set_data(nativePeer, value);
            }
        }

        internal void ThrowIfNotCreated()
        {
            if (nativePeer == nint.Zero)
                throw new InvalidOperationException("Peer not created");
        }

        public void ConfigureThrottle(uint interval, uint acceleration, uint deceleration, uint threshold)
        {
            ThrowIfNotCreated();

            Native.enet_peer_throttle_configure(nativePeer, interval, acceleration, deceleration, threshold);
        }

        public bool Send(byte channelID, ref Packet packet)
        {
            ThrowIfNotCreated();

            packet.ThrowIfNotCreated();

            return Native.enet_peer_send(nativePeer, channelID, packet.NativeData) == 0;
        }

        public bool Receive(out byte channelID, out Packet packet)
        {
            ThrowIfNotCreated();

            nint nativePacket = Native.enet_peer_receive(nativePeer, out channelID);

            if (nativePacket != nint.Zero)
            {
                packet = new Packet(nativePacket);

                return true;
            }

            packet = default;

            return false;
        }

        public void Ping()
        {
            ThrowIfNotCreated();

            Native.enet_peer_ping(nativePeer);
        }

        public void PingInterval(uint interval)
        {
            ThrowIfNotCreated();

            Native.enet_peer_ping_interval(nativePeer, interval);
        }

        public void Timeout(uint timeoutLimit, uint timeoutMinimum, uint timeoutMaximum)
        {
            ThrowIfNotCreated();

            Native.enet_peer_timeout(nativePeer, timeoutLimit, timeoutMinimum, timeoutMaximum);
        }

        public void Disconnect(uint data)
        {
            ThrowIfNotCreated();

            Native.enet_peer_disconnect(nativePeer, data);
        }

        public void DisconnectNow(uint data)
        {
            ThrowIfNotCreated();

            Native.enet_peer_disconnect_now(nativePeer, data);
        }

        public void DisconnectLater(uint data)
        {
            ThrowIfNotCreated();

            Native.enet_peer_disconnect_later(nativePeer, data);
        }

        public void Reset()
        {
            ThrowIfNotCreated();

            Native.enet_peer_reset(nativePeer);
        }
    }

    public static class Extensions
    {
        public static int StringLength(this byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            int i;

            for (i = 0; i < data.Length && data[i] != 0; i++) ;

            return i;
        }
    }

    public static class Library
    {
        public const uint maxChannelCount = 0xFF;
        public const uint maxPeers = 0xFFF;
        public const uint maxPacketSize = 32 * 1024 * 1024;
        public const uint throttleThreshold = 40;
        public const uint throttleScale = 32;
        public const uint throttleAcceleration = 2;
        public const uint throttleDeceleration = 2;
        public const uint throttleInterval = 5000;
        public const uint timeoutLimit = 32;
        public const uint timeoutMinimum = 5000;
        public const uint timeoutMaximum = 30000;
        public const uint version = 2 << 16 | 5 << 8 | 2;

        public static uint Time
        {
            get
            {
                return Native.enet_time_get();
            }
        }

        public static bool Initialize()
        {
            if (Native.enet_linked_version() != version)
                throw new InvalidOperationException("Incompatible version");

            return Native.enet_initialize() == 0;
        }

        public static bool Initialize(Callbacks callbacks)
        {
            if (callbacks == null)
                throw new ArgumentNullException("callbacks");

            if (Native.enet_linked_version() != version)
                throw new InvalidOperationException("Incompatible version");

            ENetCallbacks nativeCallbacks = callbacks.NativeData;

            return Native.enet_initialize_with_callbacks(version, ref nativeCallbacks) == 0;
        }

        public static void Deinitialize()
        {
            Native.enet_deinitialize();
        }

        public static ulong CRC64(nint buffers, int bufferCount)
        {
            return Native.enet_crc64(buffers, bufferCount);
        }
    }

    [SuppressUnmanagedCodeSecurity]
    internal static class Native
    {
#if __IOS__ || UNITY_IOS && !UNITY_EDITOR
			private const string nativeLibrary = "__Internal";
#else
        private const string nativeLibrary = "./enet.dll";
#endif

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_initialize();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_initialize_with_callbacks(uint version, ref ENetCallbacks inits);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_deinitialize();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_linked_version();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_time_get();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_crc64(nint buffers, int bufferCount);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_address_set_ip(ref ENetAddress address, string ip);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_address_set_hostname(ref ENetAddress address, string hostName);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_address_get_ip(ref ENetAddress address, StringBuilder ip, nint ipLength);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_address_get_hostname(ref ENetAddress address, StringBuilder hostName, nint nameLength);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_packet_create(byte[] data, nint dataLength, PacketFlags flags);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_packet_create(nint data, nint dataLength, PacketFlags flags);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_packet_create_offset(byte[] data, nint dataLength, nint dataOffset, PacketFlags flags);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_packet_create_offset(nint data, nint dataLength, nint dataOffset, PacketFlags flags);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_packet_check_references(nint packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_packet_get_data(nint packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_packet_get_user_data(nint packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_packet_set_user_data(nint packet, nint userData);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_packet_get_length(nint packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_packet_set_free_callback(nint packet, nint callback);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_packet_dispose(nint packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_host_create(ref ENetAddress address, nint peerLimit, nint channelLimit, uint incomingBandwidth, uint outgoingBandwidth, int bufferSize);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_host_create(nint address, nint peerLimit, nint channelLimit, uint incomingBandwidth, uint outgoingBandwidth, int bufferSize);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_host_connect(nint host, ref ENetAddress address, nint channelCount, uint data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_broadcast(nint host, byte channelID, nint packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_broadcast_exclude(nint host, byte channelID, nint packet, nint excludedPeer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_broadcast_selective(nint host, byte channelID, nint packet, nint[] peers, nint peersLength);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_host_service(nint host, out ENetEvent @event, uint timeout);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_host_check_events(nint host, out ENetEvent @event);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_channel_limit(nint host, nint channelLimit);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_bandwidth_limit(nint host, uint incomingBandwidth, uint outgoingBandwidth);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_peers_count(nint host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_packets_sent(nint host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_packets_received(nint host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_bytes_sent(nint host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_host_get_bytes_received(nint host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_set_max_duplicate_peers(nint host, ushort number);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_set_intercept_callback(nint host, nint callback);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_set_checksum_callback(nint host, nint callback);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_flush(nint host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_destroy(nint host);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_host_prevent_connections(nint host, byte state);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_throttle_configure(nint peer, uint interval, uint acceleration, uint deceleration, uint threshold);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_id(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_peer_get_ip(nint peer, byte[] ip, nint ipLength);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ushort enet_peer_get_port(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_mtu(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern PeerState enet_peer_get_state(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_rtt(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_last_rtt(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_lastsendtime(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint enet_peer_get_lastreceivetime(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_peer_get_packets_sent(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_peer_get_packets_lost(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern float enet_peer_get_packets_throttle(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_peer_get_bytes_sent(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong enet_peer_get_bytes_received(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_peer_get_data(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_set_data(nint peer, nint data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int enet_peer_send(nint peer, byte channelID, nint packet);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern nint enet_peer_receive(nint peer, out byte channelID);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_ping(nint peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_ping_interval(nint peer, uint pingInterval);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_timeout(nint peer, uint timeoutLimit, uint timeoutMinimum, uint timeoutMaximum);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_disconnect(nint peer, uint data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_disconnect_now(nint peer, uint data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_disconnect_later(nint peer, uint data);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void enet_peer_reset(nint peer);
    }
}
