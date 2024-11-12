using MultiPlug.Base.Security;

namespace MultiPlug.Auth.Machine.Models
{
    public class AUser : IUser
    {
        private string m_User;
        private bool m_Enabled;
        private string[] m_TokenName;

        public AUser(string theUser, bool isEnabled, string[] theTokenNames)
        {
            m_User = theUser;
            m_Enabled = isEnabled;
            m_TokenName = theTokenNames;
        }

        public bool Enabled
        {
            get
            {
                return m_Enabled;
            }
        }

        public string User
        {
            get
            {
                return m_User;
            }
        }

        public string[] TokenName
        {
            get
            {
                return m_TokenName;
            }
        }
    }
}