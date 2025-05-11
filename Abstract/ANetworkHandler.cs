using SimpleNetLib_ENet.Wrapper;
using SimpleNetLibCore.Abstractions;
using SimpleNetLibCore.Packet.Generic;
using SimpleNetLibCore.Packet.LowLevel;
using SimpleNetLibCore.Utils;
using SimpleNetLib_ENet.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleNetLib_ENet.Abstract
{
    public abstract class AENetNetworkHandler : ANetworkHandler
    {
        public Peer localPeer { protected get; set; }
        protected Host? host;

        public UserList userList = new UserList();

        public void SendToUser(NetworkPacket packet, Object peer, PacketFlags packetFlags = PacketFlags.None, byte channelId = 0)
        {
            Packet p = new Packet();
            byte[] buffer = new PacketWrap(packet).Serialize();
            p.Create(buffer, 0, buffer.Length, packetFlags);

            ((Peer)peer).Send(channelId, ref p);
        }

        public void SendToUser(NetworkPacket packet, User user, PacketFlags packetFlags = PacketFlags.None, byte channelId = 0)
        {
            Packet p = new Packet();
            byte[] buffer = new PacketWrap(packet).Serialize();
            p.Create(buffer, 0, buffer.Length, packetFlags);

            ((Peer)user.enetPeer).Send(channelId, ref p);
        }

        public void SendToServer(NetworkPacket packet, PacketFlags packetFlags, byte channelID = 0)
        {
            Packet p = new Packet();
            byte[] buffer = new PacketWrap(packet).Serialize();
            p.Create(buffer, 0, buffer.Length, packetFlags);

            localPeer.Send(channelID, ref p);
        }

        public override void Disconnect()
        {
            if (localPeer.State == PeerState.Connected)
                localPeer.Disconnect(0);

            host?.Dispose();
        }

        protected override void Broadcast(byte channelId, object packet)
        {
            Packet p = (Packet)packet;
            host?.Broadcast(channelId, ref p);
        }

        public override void Listen()
        {
            if (host == null)
                return;

            Event netEvent = default(Event);

            if (host?.Service(Timeout, out netEvent) > 0)
            {
                switch (netEvent.Type)
                {
                    case EventType.Disconnect:
                        ProcessDisconnectionPacket(netEvent);
                        break;
                    case EventType.Timeout:
                        ALogHandler.Instance?.LogWarning(string.Format("Client ({0}:{1}) Timed Out.", netEvent.Peer.IP, netEvent.Peer.Port));
                        break;
                    case EventType.Connect:
                        OnConnected(netEvent);
                        break;
                    case EventType.Receive:
                        ProcessNetworkEvent(netEvent);
                        break;
                    case EventType.None:
                        break;

                }

                netEvent.Packet.Dispose();
            }
        }

        protected override void ManualBroadcast(NetworkPacket packet, byte channelId, SimpleNetLibCore.GenericAPI.Flags.PacketFlags packetFlags)
        {
            foreach (User u in userList.users)
            {
                if (((Peer)u.enetPeer).State == PeerState.Connected)
                {
                    SendToUser(packet, u, packetFlags.ConvertTo(), channelId);
                }
            }
        }

        protected abstract void OnConnected(Event @event);
        protected abstract void ProcessNetworkEvent(Event @event);
        protected abstract void ProcessTimeoutPacket(Event @event);
        protected abstract void ProcessDisconnectionPacket(Event @event);

        protected override void OnConnected(object e) => OnConnected((Event)e);
        protected override void ProcessDisconnectionPacket(object e) => ProcessDisconnectionPacket((Event)e);
        protected override void ProcessTimeoutPacket(object e) => ProcessTimeoutPacket((Event)e);
        protected override void ProcessNetworkEvent(object e) => ProcessNetworkEvent((Event)e);

        public override void SendToServer(NetworkPacket packet, SimpleNetLibCore.GenericAPI.Flags.PacketFlags packetFlags, byte channelID = 0) => SendToServer(packet, packetFlags.ConvertTo(), channelID);
        public override void SendToUser(NetworkPacket packet, object peer, SimpleNetLibCore.GenericAPI.Flags.PacketFlags packetFlags = SimpleNetLibCore.GenericAPI.Flags.PacketFlags.None, byte channelId = 0) => SendToUser(packet, peer, packetFlags.ConvertTo(), channelId);
        public override void SendToUser(NetworkPacket packet, User user, SimpleNetLibCore.GenericAPI.Flags.PacketFlags packetFlags = SimpleNetLibCore.GenericAPI.Flags.PacketFlags.None, byte channelId = 0) => SendToUser(packet, user, packetFlags.ConvertTo(), channelId);

    }
}
