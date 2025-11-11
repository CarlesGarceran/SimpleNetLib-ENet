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
    public abstract class ENetNetworkHandler : ANetworkHandler
    {
        public Peer localPeer { protected get; set; }
        protected Host? host;

        public UserList userList = new UserList();

        protected ENetNetworkHandler() : base()
        {
            Instance = this;
        }

        public void SendToUser(NetworkPacket packet, Object _peer, PacketFlags packetFlags = PacketFlags.None, byte channelId = 0)
        {
            Packet p = new Packet();
            byte[] buffer = new PacketWrap(packet).Serialize();
            p.Create(buffer, 0, buffer.Length, packetFlags);

            Peer peer = ((Peer)_peer);

            if (peer.State == PeerState.Connected)
            {
                peer.Send(channelId, ref p);
            }
            else
            {
                ALogHandler.Instance?.LogError("Attempt to send packet to disconnected peer");
            }
        }

        public void SendToUser(NetworkPacket packet, User user, PacketFlags packetFlags = PacketFlags.None, byte channelId = 0)
        {
            Packet p = new Packet();
            byte[] buffer = new PacketWrap(packet).Serialize();
            p.Create(buffer, 0, buffer.Length, packetFlags);

            Peer peer = ((Peer)user.socket);
            
            if(peer.State == PeerState.Connected)
            {
                peer.Send(channelId, ref p);
            }
            else
            {
                ALogHandler.Instance?.LogError("Attempt to send packet to disconnected peer");
            }
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
                ALogHandler.Instance?.LogInfo("PACKET RETRIEVED");
                ALogHandler.Instance?.LogInfo("PACKET TYPE: " + netEvent.Type);

                if(netEvent.Type == EventType.Receive)
                    ALogHandler.Instance?.LogInfo("PACKET SIZE: " + netEvent.Packet.Length);

                ALogHandler.Instance?.LogInfo("PACKET OWNER: " + netEvent.Peer.IP + ":" + netEvent.Peer.Port);
                ALogHandler.Instance?.LogInfo("PACKET CHANNEL: " + netEvent.ChannelID);

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

        protected override void ManualBroadcast(NetworkPacket packet, byte channelId, int packetFlags)
        {
            foreach (User u in userList.users)
            {
                if (((Peer)u.socket).State == PeerState.Connected)
                {
                    SendToUser(packet, u, (PacketFlags)packetFlags, channelId);
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

        public override void SendToServer(NetworkPacket packet, int packetFlags, byte channelID = 0) => SendToServer(packet, (PacketFlags)packetFlags, channelID);
        public override void SendToUser(NetworkPacket packet, object peer, int packetFlags, byte channelId = 0) => SendToUser(packet, peer, (PacketFlags)packetFlags, channelId);
        public override void SendToUser(NetworkPacket packet, User user, int packetFlags, byte channelId = 0) => SendToUser(packet, user, (PacketFlags)packetFlags, channelId);

        public override void SendToServer(NetworkPacket packet, string packetFlags, byte channelID = 0) => SendToServer(packet, Enum.Parse<PacketFlags>(packetFlags), channelID);
        public override void SendToUser(NetworkPacket packet, object peer, string packetFlags, byte channelId = 0) => SendToUser(packet, peer, Enum.Parse<PacketFlags>(packetFlags), channelId);
        public override void SendToUser(NetworkPacket packet, User user, string packetFlags, byte channelId = 0) => SendToUser(packet, user, Enum.Parse<PacketFlags>(packetFlags), channelId);
    }
}
