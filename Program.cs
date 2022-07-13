using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

try
{
    if (args.Length <= 1)
    {
        Console.WriteLine("Uso CIE.XMLSign [file xml da firmare] [nome certificato]");
        return;
    }

    var certificate = GetCertificateFromStore(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindBySubjectName, args[1], false);
    RSA rsaKey = certificate.GetRSAPrivateKey();

    // Create a new XML document.
    XmlDocument xmlDoc = new XmlDocument();

    // Load an XML file into the XmlDocument object.
    xmlDoc.PreserveWhitespace = true;
    xmlDoc.Load(args[0]);

    // Sign the XML document.
    SignXml(xmlDoc, rsaKey, certificate);

    Console.WriteLine("XML file signed.");

    // Save the document.
    xmlDoc.Save($"{args[0]}_signed.xml");
}
catch (Exception e)
{
    Console.WriteLine(e.Message);
}

static void SignXml(XmlDocument xmlDoc, RSA rsaKey, X509Certificate2 certificate)
{
    // Check arguments.
    if (xmlDoc == null)
        throw new ArgumentException(nameof(xmlDoc));
    if (rsaKey == null)
        throw new ArgumentException(nameof(rsaKey));

    // Create a SignedXml object.
    SignedXml signedXml = new SignedXml(xmlDoc);

    // Add the key to the SignedXml document.
    signedXml.SigningKey = rsaKey;

    // Create a reference to be signed.
    Reference reference = new Reference();
    reference.Uri = "";

    // Add an enveloped transformation to the reference.
    XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
    reference.AddTransform(env);

    // Add the reference to the SignedXml object.
    signedXml.AddReference(reference);

    KeyInfo keyInfo = new KeyInfo();
    keyInfo.AddClause(new KeyInfoX509Data(certificate));
    signedXml.KeyInfo = keyInfo;


    // Compute the signature.
    signedXml.ComputeSignature();

    // Get the XML representation of the signature and save
    // it to an XmlElement object.
    XmlElement xmlDigitalSignature = signedXml.GetXml();

    // Append the element to the XML document.
    //xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
    xmlDoc.DocumentElement.InsertBefore(xmlDigitalSignature, xmlDoc.DocumentElement.ChildNodes[0]);
}

static X509Certificate2 GetCertificateFromStore(StoreLocation storeLocation, StoreName storeName, X509FindType findType, object findValue, bool validOnly)
{
    using X509Store store = new X509Store(storeName, storeLocation);
    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
    X509Certificate2Collection coll = store.Certificates.Find(findType, findValue.ToString(), validOnly);

    X509Certificate2 certificate = null;
    if (coll.Count > 0)
    {
        certificate = coll[0];
    }

    return certificate;
}
