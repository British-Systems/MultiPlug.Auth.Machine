using System.Xml.Serialization;

namespace MultiPlug.Auth.Machine.Models.File
{
    public class FileUser
    {
        [XmlAttribute("username")]
        public string Username { get; set; }
        [XmlAttribute("enabled")]
        public bool Enabled { get; set; }
        [XmlArray("tokens")]
        [XmlArrayItem("add")]
        public FileToken[] Tokens { get; set; }
    }
}
