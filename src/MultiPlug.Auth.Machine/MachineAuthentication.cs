using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Management;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using MultiPlug.Base.Security;


using MultiPlug.Auth.Machine.Models;
using MultiPlug.Auth.Machine.File;
using MultiPlug.Auth.Machine.Models.File;

namespace MultiPlug.Auth.Machine
{
    public class MachineAuthentication : IAuthentication
    {
        private string[] m_Domains;
        private static readonly Scheme[] c_Schemes = { Scheme.Form, Scheme.Basic, Scheme.BearerToken };
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
                return new AuthResult(false, new AUser(theCredentials.Username, false, new string[0]), "Operation only supported on Windows");
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

                return new AuthResult(true, new AUser(theCredentials.Username, true, new string[0]), string.Empty);
            }
            catch (Exception ex)
            {
                return new AuthResult(false, new AUser(theCredentials.Username, false, new string[0]), ex.Message);
            }
        }

        public IAuthResult Edit(IAuthCredentials theCredentials, IAuthCredentials theNewCredentials)
        {
            if (!string.IsNullOrEmpty(theNewCredentials.Password))
            {
                return new AuthResult(false, new AUser(theCredentials.Username, false, new string[0]), "Use Microsoft Windows to change passwords");
            }

            FileBody File = FileManager.Read();

            var Search = FileManager.SearchUser(File, theCredentials.Username);

            // New Tokens
            var AuthHeader = GetAuthHeader(theNewCredentials.HttpRequestHeaders);
            var AuthFriendlyName = GetAuthFriendlyNameHeader(theNewCredentials.HttpRequestHeaders);

            FileToken[] NewTokens = new FileToken[0];

            if (AuthHeader != null && AuthFriendlyName != null && AuthHeader.Length == AuthFriendlyName.Length)
            {
                NewTokens = new FileToken[AuthHeader.Length];

                for (int i = 0; i < AuthHeader.Length; i++)
                {
                    NewTokens[i] = new FileToken { Value = AuthHeader[i], FriendlyName = AuthFriendlyName[i] };
                }
            }
            else
            {
                if(Search == null)
                {
                    return new AuthResult(false, new AUser(FileManager.GetFullUsername(m_Domains[0], theCredentials.Username), false, FileManager.GetUserTokens(Search)), "Not Modified" );
                }
                else
                {
                    return new AuthResult(false, new AUser(FileManager.GetFullUsername(m_Domains[0], Search.Username), Search.Enabled, FileManager.GetUserTokens(Search)), "Not Modified" );
                }
            }

            if (Search == null)
            {
                Search = new FileUser { Enabled = false, Username = theCredentials.Username, Tokens = NewTokens };
                FileManager.AddUser(File, Search);
            }
            else
            {
                FileManager.AddTokens(Search, NewTokens);
            }

            FileManager.Write(File);

            return new AuthResult(true, new AUser(FileManager.GetFullUsername(m_Domains[0], Search.Username), Search.Enabled, FileManager.GetUserTokens(Search).ToArray()), "OK" );
        }

        public IAuthResult Delete(IAuthCredentials theCredentials)
        {
            var AuthFriendlyName = GetAuthFriendlyNameHeader(theCredentials.HttpRequestHeaders);

            if (AuthFriendlyName != null)
            {
                FileBody File = FileManager.Read();

                var UserSearch = FileManager.SearchUser(File, theCredentials.Username);

                if (UserSearch != null)
                {
                    if( FileManager.RemoveTokens(UserSearch, AuthFriendlyName))
                    {
                        if(UserSearch.Tokens == null || UserSearch.Tokens.Length == 0 && UserSearch.Enabled == false)
                        {
                            FileManager.DeleteUser(File, UserSearch);
                        }

                        FileManager.Write(File);

                        return new AuthResult(true, new AUser(FileManager.GetFullUsername(m_Domains[0], UserSearch.Username), UserSearch.Enabled, FileManager.GetUserTokens(UserSearch)), "OK");
                    }
                    else
                    {
                        return new AuthResult(false, new AUser(FileManager.GetFullUsername(m_Domains[0], UserSearch.Username), UserSearch.Enabled, FileManager.GetUserTokens(UserSearch)), "Token Not Found");
                    }
                }
                else
                {
                    return new AuthResult(false, new AUser(FileManager.GetFullUsername(m_Domains[0], theCredentials.Username), false, new string[0]), "User not found");
                }
            }
            else
            {
                if (Environment.OSVersion.Platform == PlatformID.Unix)
                {
                    return new AuthResult(false, null, "Operation only supported on Microsoft Windows");
                }

                FileBody File = FileManager.Read();

                var Search = FileManager.SearchUser(File, theCredentials.Username);

                if (Search != null)
                {
                    FileManager.DeleteUser(File, Search);
                    FileManager.Write(File);
                }

                try
                {
                    DirectoryEntry AD = new DirectoryEntry("WinNT://" + Environment.MachineName + ",computer");
                    DirectoryEntries entries = AD.Children;
                    DirectoryEntry user = entries.Find(theCredentials.Username);
                    entries.Remove(user);

                    return new AuthResult(true, new AUser(FileManager.GetFullUsername(m_Domains[0], theCredentials.Username), true, new string[0]), string.Empty);
                }
                catch (Exception ex)
                {
                    return new AuthResult(false, new AUser(FileManager.GetFullUsername(m_Domains[0], theCredentials.Username), false, new string[0]), ex.Message);
                }
            }
        }

        public IReadOnlyCollection<IUser> Users()
        {
            List<AUser> UserList;

            if ( Environment.OSVersion.Platform != PlatformID.Unix )
            {
                SelectQuery query = new SelectQuery("Win32_UserAccount");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);

                var SearchResult = searcher.Get();

                UserList = new List<AUser>(SearchResult.Count);

                FileBody File = FileManager.Read();

                foreach (ManagementObject envVar in SearchResult)
                {
                    string User = envVar["Name"].ToString();

                    var Search = FileManager.SearchUser(File, User);

                    if(Search == null)
                    {
                        UserList.Add(new AUser(FileManager.GetFullUsername(m_Domains[0], User), false, new string[0]));
                    }
                    else
                    {
                        UserList.Add(new AUser(FileManager.GetFullUsername(m_Domains[0], User), Search.Enabled, FileManager.GetUserTokens(Search)));
                    }
                }
            }
            else
            {
                UserList = new List<AUser>(0);
            }

            return Array.AsReadOnly(UserList.ToArray());
        }

        public IAuthResult Enable(string theUser, bool isEnabled)
        {
            FileBody File = FileManager.Read();

            var Search = FileManager.SearchUser(File, theUser);

            if(Search == null)
            {
                if(isEnabled)
                {
                    FileManager.AddUser(File, new FileUser { Enabled = isEnabled, Tokens = new FileToken[0], Username = theUser });
                    FileManager.Write(File);
                }

                return new AuthResult(false, new AUser(FileManager.GetFullUsername(m_Domains[0], theUser) , isEnabled, new string[0]), "OK");
            }
            else
            {
                if (Search.Tokens != null && Search.Tokens.Length > 0)
                {
                    Search.Enabled = isEnabled;
                }
                else
                {
                    if (isEnabled)
                    {
                        Search.Enabled = isEnabled; // true
                    }
                    else
                    {
                        FileManager.DeleteUser(File, Search); // Users are disabled by default, no need to store them in a file
                    }
                }

                FileManager.Write(File);
                return new AuthResult(false, new AUser(FileManager.GetFullUsername(m_Domains[0], theUser), isEnabled, FileManager.GetUserTokens(Search)), "OK");
            }
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
            string Identity = FileManager.GetFullUsername(m_Domains[0], Username);

            FileBody File = FileManager.Read();

            var Search = FileManager.SearchUser(File, Username);

            if (Search == null || Search.Enabled == false)
            {
                return new AuthResult(Result, new AUser(Identity, false, FileManager.GetUserTokens(Search)), "User Not Enabled");
            }

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

            return new AuthResult(Result, new AUser(Identity, true, FileManager.GetUserTokens(Search)), Message);
        }

        private IAuthResult doTokenLookUp(string Token)
        {
            FileBody File = FileManager.Read();

            FileUser UserSearch = File.Users.FirstOrDefault(User =>
            {
                if (User.Tokens != null)
                {
                    return (User.Tokens.FirstOrDefault(T => T.Value == Token) != null) ? true : false;
                }
                else
                {
                    return false;
                }
            });

            if (UserSearch != null)
            {
                if (!UserSearch.Enabled)
                {
                    return new AuthResult(false, new AUser(FileManager.GetFullUsername(m_Domains[0], UserSearch.Username), UserSearch.Enabled, FileManager.GetUserTokens(UserSearch)), "User is disabled" );
                }
                else
                {
                    return new AuthResult(true, new AUser(FileManager.GetFullUsername(m_Domains[0], UserSearch.Username), UserSearch.Enabled, FileManager.GetUserTokens(UserSearch)), "OK" );
                }
            }
            else
            {
                return new AuthResult(false, null, "User Not Found");
            }
        }

        public IAuthResult Authenticate(IAuthCredentials theCredentials)
        {
            if ( ! FileManager.Exists())
            {
                return new AuthResult(false, null, "System Error: User file does not exist");
            }

            string[] AuthorizationHeader = null;

            switch (theCredentials.Scheme)
            {
                case Scheme.Form:
                    return doLookUp(theCredentials.Username, theCredentials.Password);

                case Scheme.Basic: // Username and Password Encoded in the Authorization Header
                    AuthorizationHeader = GetAuthHeader(theCredentials.HttpRequestHeaders);

                    if (AuthorizationHeader == null)
                    {
                        return new AuthResult(false, new AUser(theCredentials.Username, false, new string[0]), "Missing Authorization Header");
                    }

                    string EncodedValue = AuthorizationHeader.First();
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
                        return new AuthResult(false, new AUser(theCredentials.Username, false, new string[0]), "Missing Domain");
                    }

                    if (Domain.Equals(m_Domains[0], StringComparison.OrdinalIgnoreCase))
                    {
                        return doLookUp(Username, Password);
                    }
                    else
                    {
                        return new AuthResult(false, new AUser(theCredentials.Username, false, new string[0]), "Domain mismatch");
                    }

                case Scheme.BearerToken:
                    AuthorizationHeader = GetAuthHeader(theCredentials.HttpRequestHeaders);

                    if (AuthorizationHeader == null)
                    {
                        return new AuthResult(false, new AUser(theCredentials.Username, false, new string[0]), "Missing Authorization Header");
                    }

                    return doTokenLookUp(AuthorizationHeader.First());

                default:
                    return new AuthResult(false, new AUser(theCredentials.Username, false, new string[0]), "Not a Supported Authentication Scheme");
            }
        }

        private string[] GetAuthHeader(IEnumerable<KeyValuePair<string, IEnumerable<string>>> theHttpRequestHeaders)
        {
            if (theHttpRequestHeaders == null)
            {
                return null;
            }

            var Search = theHttpRequestHeaders.FirstOrDefault(Header => Header.Key == c_HttpRequestHeaders[0]);

            if (Search.Equals(default(KeyValuePair<string, IEnumerable<string>>)))
            {
                return null;
            }
            else
            {
                return Search.Value.ToArray();
            }
        }

        private string[] GetAuthFriendlyNameHeader(IEnumerable<KeyValuePair<string, IEnumerable<string>>> theHttpRequestHeaders)
        {
            if (theHttpRequestHeaders == null)
            {
                return null;
            }

            var Search = theHttpRequestHeaders.FirstOrDefault(Header => Header.Key == "AuthorizationFriendlyName");

            if (Search.Equals(default(KeyValuePair<string, IEnumerable<string>>)))
            {
                return null;
            }
            else
            {
                return Search.Value.ToArray();
            }
        }
    }
}
