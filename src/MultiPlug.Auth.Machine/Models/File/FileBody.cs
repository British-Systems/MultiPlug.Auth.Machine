using System;
using System.Xml.Serialization;

namespace MultiPlug.Auth.Machine.Models.File
{
    [Serializable]
    [XmlRoot(ElementName = "MultiPlug.Auth.Machine")]
    public class FileBody
    {
        [XmlArray("users")]
        [XmlArrayItem("add")]
        public FileUser[] Users { get; set; }
    }
}
