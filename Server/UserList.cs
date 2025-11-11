using SimpleNetLib_ENet.Wrapper;
using SimpleNetLibCore.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleNetLib_ENet.Server
{
    public sealed class UserList
    {
        public List<User> users = new List<User>();

        public void AddUser(User newUser)
        {
            if(!users.Contains(newUser))
                users.Add(newUser);
        }

        public IEnumerable<User> GetUsersFromGUID(string GUID)
        {
            return users.Where((u) =>
            {
                return u.uid == GUID;
            });
        }

        public void RemoveUser(User user)
        {
            if (users.Contains(user))
                users.Remove(user);
        }

        public User? GetUserFromPeer(Peer peer)
        {
            return users.Find((u) =>
            {
                return u.socket.Equals(peer);
            });
        }

        public User? GetUserFromGUID(string GUID)
        {
            return users.Find(u => u.uid == GUID);
        }
    }
}
