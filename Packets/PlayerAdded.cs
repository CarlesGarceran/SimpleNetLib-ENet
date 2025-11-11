using SimpleNetLib_ENet.Wrapper;
using SimpleNetLibCore.Abstractions;
using SimpleNetLibCore.Packet.Generic;
using SimpleNetLib_ENet.Abstract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using JSON = Newtonsoft.Json.JsonConvert;
using SimpleNetLibCore.Utils;

namespace SimpleNetLibCore.Packet
{
    public class PlayerAdded : NetworkPacket
    {
        public bool isServer = false;
        public string generatedUID;

        public string username;

        public PlayerAdded() 
            : base(User.Instance)
        {
            this.username = User.Instance.name;
        }

        public override void ClientExecute(Object ev)
        {
            User.Instance.SetUID(generatedUID);

            ALogHandler.Instance?.Log("-- User --");
            ALogHandler.Instance?.Log("UID:"  + User.Instance.uid);
            ALogHandler.Instance?.Log("Name:" + User.Instance.name);
        }

        public override void Execute(Object ev)
        {

        }

        public override void ServerExecute(Object ev)
        {
            Event e = (Event)ev;

            PlayerAdded pAdded = new PlayerAdded()
            {
                isServer = true
            };

            pAdded.generatedUID = Guid.NewGuid().ToString();

            User user = new User(username);
            user.SetSocket(e.Peer);
            user.SetUID(pAdded.generatedUID);

            ALogHandler.Instance?.Log("-- User --");
            ALogHandler.Instance?.Log("UID:" + user.uid);
            ALogHandler.Instance?.Log("Name:" + user.name);

            ((ENetNetworkHandler?)ANetworkHandler.Instance)?.userList.AddUser(user);

            ANetworkHandler.Instance?.SendToUser(pAdded, e.Peer);
        }
    }
}
