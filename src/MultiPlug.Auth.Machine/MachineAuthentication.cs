using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using MultiPlug.Base.Security;

namespace MultiPlug.Auth.Machine
{
    public class MachineAuthentication : IAuthentication
    {
        private string[] m_Domains;

        public MachineAuthentication()
        {
            m_Domains = Environment.OSVersion.Platform == PlatformID.Unix ? new string[0] : new string[] { "Machine" };
        }

        public IReadOnlyCollection<string> Domains
        {
            get
            {
                return Array.AsReadOnly(m_Domains);
            }
        }

        public IAuthResult Authenticate(IAuthCredentials theCredentials)
        {
            bool Result = false;
            string Message = "OK";

            try
            {
                using (PrincipalContext Context = new PrincipalContext(ContextType.Machine))
                {
                    try
                    {
                        Result = Context.ValidateCredentials(theCredentials.Username, theCredentials.Password);
                    }
                    catch (System.Runtime.InteropServices.COMException)
                    {
                    }
                    catch (ArgumentException)
                    {
                    }
                    catch (Exception ex)
                    {
                        Message = ex.Message;
                    }
                }
            }
            catch (Exception ex)
            {
                Message = ex.Message;
            }

            return new AuthResult(Result, Message);
        }
    }
}
