using SimpleNetLib_ENet.Wrapper;
using SimpleNetLibCore.Abstractions;
using SimpleNetLibCore.Packet;
using SimpleNetLibCore.Packet.Generic;
using SimpleNetLibCore.Packet.LowLevel;
using SimpleNetLibCore.Utils;
using SimpleNetLib_ENet.Abstract;
using SimpleNetLib_ENet.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

using JSON = Newtonsoft.Json.JsonConvert;

namespace SimpleNetLib_ENet.Server
{
    public class NetworkServer : AENetNetworkHandler
    {
        public NetworkServer(int listenPort, int peerLimit = 32) : base()
        {
            if (!SimpleNetLibCore.Library.IsInitialized)
                return;

            Library.Initialize();

            ALogHandler.Instance?.Log("################################");
            ALogHandler.Instance?.Log("##    (SNL)  SIMPLE NET LIB   ##");
            ALogHandler.Instance?.Log("################################");

            IsClient = false;
            IsServer = true;

            host = new Host();
            Address address = new Address();
            address.Port = (ushort)listenPort;

            ALogHandler.Instance?.Log("Initializing Server...");
            host.Create(address, peerLimit, 1);
            address.SetHost("127.0.0.1");
            localPeer = host.Connect(address);
            ALogHandler.Instance?.Log("Server Initialized (Listening on " + address.GetIP() + ":" + address.Port + ")");
        }

        protected override void ProcessDisconnectionPacket(Event @e)
        {
            User? u = userList.GetUserFromPeer(e.Peer);
            if (u is not null)
                userList.RemoveUser(u);
        }

        protected override void ProcessTimeoutPacket(Event e)
        {
            User? u = userList.GetUserFromPeer(e.Peer);
            if (u is not null)
                userList.RemoveUser(u);
        }

        protected override void OnConnected(Event @event)
        {
            ALogHandler.Instance?.LogWarning(string.Format("Client ({0}:{1}) Connected.", @event.Peer.IP, @event.Peer.Port));
        }

        protected override void ProcessNetworkEvent(Event @event)
        {
            byte[] payload = UnmanagedHandler.GetPacketBuffer(@event.Packet);

            try
            {
                PacketWrap packetWrap = Compressor.Decompress<PacketWrap>(payload);

                NetworkPacket? p = packetWrap.Deserialize();
                ServerExecute(p, @event);
            }
            catch (Exception e)
            {
                ALogHandler.Instance?.LogError(e.Message);
            }
        }
    }
}
