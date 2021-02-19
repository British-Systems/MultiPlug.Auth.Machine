using System;
using MultiPlug.Base.Security;

namespace MultiPlug.Auth.Machine
{
    internal class AuthResult : IAuthResult
    {
        private string m_Message;
        private bool m_Result;
        private string m_Identity;

        public AuthResult(bool theResult, string theIdentity, string theMessage)
        {
            m_Result = theResult;
            m_Message = theMessage;
            m_Identity = theIdentity;
        }

        public string Identity
        {
            get
            {
                return m_Identity;
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