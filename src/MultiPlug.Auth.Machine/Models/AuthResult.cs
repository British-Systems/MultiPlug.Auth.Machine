using MultiPlug.Base.Security;

namespace MultiPlug.Auth.Machine.Models
{
    internal class AuthResult : IAuthResult
    {
        private string m_Message;
        private bool m_Result;
        private IUser m_User;

        public AuthResult(bool theResult, IUser theUser, string theMessage)
        {
            m_Result = theResult;
            m_Message = theMessage;
            m_User = theUser;
        }

        public IUser User
        {
            get
            {
                return m_User;
            }
        }

        public string Message
        {
            get
            {
                return m_Message;
            }
        }

        public bool Result
        {
            get
            {
                return m_Result;
            }
        }
    }
}