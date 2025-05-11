using SimpleNetLib_ENet.Wrapper;
using SimpleNetLibCore.Abstractions;
using SimpleNetLibCore.Local;
using SimpleNetLibCore.Packet.Generic;
using SimpleNetLib_ENet.Abstract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using JSON = Newtonsoft.Json.JsonConvert;

namespace SimpleNetLibCore.Packet
{
    public class PlayerAdded : NetworkPacket
    {
        public bool isServer = false;

        public string username;
        public string uid;

        public PlayerAdded(string username, string uid)
        {
            this.username = username;
            this.uid = uid;
        }

        public override void ClientExecute(Object ev)
        {

        }

        public override void Execute(Object ev)
        {

        }

        public override void ServerExecute(Object ev)
        {
            Event e = (Event)ev;

            PlayerAdded pAdded = new PlayerAdded(LocalUser.Instance.userName, LocalUser.Instance.uid)
            {
                isServer = true
            };

            ((AENetNetworkHandler?)ANetworkHandler.Instance)?.userList.AddUser(new Utils.User()
            {
                enetPeer = e.Peer,
                name = username,
                uid = uid
            });

            ANetworkHandler.Instance?.SendToUser(pAdded, e.Peer);
        }
    }
}
