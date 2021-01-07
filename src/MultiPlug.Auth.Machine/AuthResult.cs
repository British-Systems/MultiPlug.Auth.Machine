using MultiPlug.Base.Security;

namespace MultiPlug.Auth.Machine
{
    internal class AuthResult : IAuthResult
    {
        private string m_Message;
        private bool m_Result;

        public AuthResult(bool theResult, string theMessage)
        {
            m_Result = theResult;
            m_Message = theMessage;
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