using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using MultiPlug.Base.Security;
using System.Management;
using System.DirectoryServices;

namespace MultiPlug.Auth.Machine
{
    public class MachineAuthentication : IAuthentication
    {
        private string[] m_Domains;
        private static readonly Scheme[] c_Schemes = { Scheme.Form, Scheme.Basic };
        private static readonly string[] c_HttpRequestHeaders = { "Authorization" };
        private static readonly string[] c_HttpQueryKeys = { "Username", "Password", "Authorization" };

        public MachineAuthentication()
        {
            m_Domains = Environment.OSVersion.Platform == PlatformID.Unix ? new string[0] : new string[] { "Machine" };
        }

        public IAuthResult Add(IAuthCredentials theCredentials)
        {
            if(Environment.OSVersion.Platform == PlatformID.Unix)
            {
                return new AuthResult(false, string.Empty, "Operation only supported on Windows");
            }

            try
            {
                DirectoryEntry AD = new DirectoryEntry("WinNT://" + Environment.MachineName + ",computer");
                DirectoryEntry NewUser = AD.Children.Add(theCredentials.Username, "user");
                NewUser.Invoke("SetPassword", new object[] { theCredentials.Password });
                NewUser.Invoke("Put", new object[] { "Description", "User created by MultiPlug" });
                NewUser.CommitChanges();
                DirectoryEntry grp;

                grp = AD.Children.Find("Guests", "group");
                if (grp != null) { grp.Invoke("Add", new object[] { NewUser.Path.ToString() }); }

                return new AuthResult(true, theCredentials.Username, string.Empty);
            }
            catch (Exception ex)
            {
                return new AuthResult(false, string.Empty, ex.Message);
            }
        }

        public IAuthResult Edit(IAuthCredentials theCredentials, IAuthCredentials theNewCredentials)
        {
            return new AuthResult(false, string.Empty, "Use Windows to change users or passwords");
        }

        public IAuthResult Delete(IAuthCredentials theCredentials)
        {
            if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                return new AuthResult(false, string.Empty, "Operation only supported on Windows");
            }

            try
            {
                DirectoryEntry AD = new DirectoryEntry("WinNT://" + Environment.MachineName + ",computer");
                DirectoryEntries entries = AD.Children;
                DirectoryEntry user = entries.Find(theCredentials.Username);
                entries.Remove(user);

                return new AuthResult(true, theCredentials.Username, string.Empty);
            }
            catch (Exception ex)
            {
                return new AuthResult(false, string.Empty, ex.Message);
            }

        }

        public IReadOnlyCollection<string> Users()
        {
            List<string> UserList;

            if ( Environment.OSVersion.Platform != PlatformID.Unix )
            {
                SelectQuery query = new SelectQuery("Win32_UserAccount");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);

                var SearchResult = searcher.Get();

                UserList = new List<string>(SearchResult.Count);

                foreach (ManagementObject envVar in SearchResult)
                {
                    UserList.Add(m_Domains[0] + "\\" + envVar["Name"].ToString());
                }
            }
            else
            {
                UserList = new List<string>(0);
            }

            return Array.AsReadOnly(UserList.ToArray());
        }

        public IReadOnlyCollection<string> Domains
        {
            get
            {
                return Array.AsReadOnly(m_Domains);
            }
        }

        public IReadOnlyCollection<string> HttpRequestHeaders
        {
            get
            {
                return Array.AsReadOnly(c_HttpRequestHeaders);
            }
        }

        public IReadOnlyCollection<string> HttpQueryKeys
        {
            get
            {
                return Array.AsReadOnly(c_HttpQueryKeys);
            }
        }

        public IReadOnlyCollection<Scheme> Schemes
        {
            get
            {
                return Array.AsReadOnly(c_Schemes);
            }
        }

        private IAuthResult doLookUp(string Username, string Password)
        {
            bool Result = false;
            string Message = "OK";
            string Identity = string.Empty;

            try
            {
                using (PrincipalContext Context = new PrincipalContext(ContextType.Machine))
                {
                    try
                    {
                        Result = Context.ValidateCredentials(Username, Password);
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

            if(Result)
            {
                Identity = m_Domains[0] + "\\" + Username;
            }

            return new AuthResult(Result, Identity, Message);
        }

        public IAuthResult Authenticate(IAuthCredentials theCredentials)
        {
            if (theCredentials.Scheme == Scheme.Form)
            {
                return doLookUp(theCredentials.Username, theCredentials.Password);
            }
            else if (theCredentials.Scheme == Scheme.Basic && theCredentials.HttpRequestHeaders != null) // Basic
            {
                KeyValuePair<string, IEnumerable<string>> AuthorizationHeader = theCredentials.HttpRequestHeaders.FirstOrDefault(Header => Header.Key == c_HttpRequestHeaders[0]);

                if (AuthorizationHeader.Equals(new KeyValuePair<string, IEnumerable<string>>()))
                {
                    return new AuthResult(false, string.Empty, "Missing Authorization Header" );
                }

                if (AuthorizationHeader.Value != null && AuthorizationHeader.Value.Count() > 0)
                {
                    string EncodedValue = AuthorizationHeader.Value.First();
                    string DecodedValue = Encoding.UTF8.GetString(Convert.FromBase64String(EncodedValue));
                    string DomainAndUsername = DecodedValue.Substring(0, DecodedValue.IndexOf(":"));
                    string Password = DecodedValue.Substring(DecodedValue.IndexOf(":") + 1);

                    int IndexOfSlash = DomainAndUsername.IndexOf("\\");

                    string Domain;
                    string Username;

                    if (IndexOfSlash != -1)
                    {
                        Domain = DomainAndUsername.Substring(0, IndexOfSlash);
                        Username = DomainAndUsername.Substring(IndexOfSlash + 1);
                    }
                    else
                    {
                        return new AuthResult(false, string.Empty, "Missing Domain");
                    }

                    if (Domain.Equals(m_Domains[0], StringComparison.OrdinalIgnoreCase))
                    {
                        return doLookUp(Username, Password);
                    }
                    else
                    {
                        return new AuthResult( false, string.Empty, "Domain mismatch" );
                    }
                }
                else
                {
                    return new AuthResult(false, string.Empty, "Missing value in Authorization Header" );
                }
            }
            else
            {
                return new AuthResult(false, string.Empty, "Not a supported Scheme" );
            }
        }
    }
}
