using System.Xml.Serialization;

namespace MultiPlug.Auth.Machine.Models.File
{
    public class FileToken
    {
        [XmlAttribute("token")]
        public string Value { get; set; }
        [XmlAttribute("name")]
        public string FriendlyName { get; set; }
    }
}
