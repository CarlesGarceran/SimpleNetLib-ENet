using SimpleNetLibCore.Abstractions;
using SimpleNetLibCore.Packet;
using SimpleNetLibCore.Packet.Generic;
using SimpleNetLibCore.Packet.LowLevel;
using SimpleNetLibCore.Store.Attributes;
using SimpleNetLibCore.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SimpleNetLib_ENet.Utils;
using SimpleNetLib_ENet.Wrapper;
using SimpleNetLib_ENet.Abstract;

namespace SimpleNetLib_ENet.Client
{
    public class NetworkClient : ENetNetworkHandler
    {
        public NetworkClient(string address, int port) : base()
        {
            if (!SimpleNetLibCore.Library.IsInitialized)
                return;

            Library.Initialize();

            ALogHandler.Instance?.Log("################################");
            ALogHandler.Instance?.Log("##    (SNL)  SIMPLE NET LIB   ##");
            ALogHandler.Instance?.Log("################################");

            this.IsClient = true;
            this.IsServer = false;

            host = new Host();

            Address addr = new Address();
            addr.SetHost(address);
            addr.Port = (ushort)port;

            ALogHandler.Instance?.Log("Initializing Client...");

            host.Create();

            localPeer = host.Connect(addr);
            User.Instance.SetSocket(localPeer);
        }

        protected override void ProcessDisconnectionPacket(Event e)
        {
            localPeer.DisconnectNow(0);
            host?.Dispose();
        }

        protected override void ProcessTimeoutPacket(Event e)
        {
            localPeer.DisconnectNow(0);
            host?.Dispose();
        }

        protected override void ProcessNetworkEvent(Event @event)
        {
            byte[] payload = UnmanagedHandler.GetPacketBuffer(@event.Packet);

            try
            {
                PacketWrap packetWrap = Compressor.Decompress<PacketWrap>(
                    SimpleNetLibCore.Library.Settings.PacketEncrypter.DecryptBuffer(payload)
                );

                NetworkPacket p = packetWrap.Deserialize();
                this.ClientExecute(p, @event);
            }
            catch (Exception e)
            {
                ALogHandler.Instance?.LogError(e.Message);
            }
        }

        protected override void OnConnected(Event @event)
        {
            ALogHandler.Instance?.Log("Client Initialized (Connected to " + @event.Peer.IP + ":" + @event.Peer.Port + ")");
            PlayerAdded playerAddedPacket = new PlayerAdded();
            this.SendToServer(playerAddedPacket, PacketFlags.Reliable);
        }
    }
}
