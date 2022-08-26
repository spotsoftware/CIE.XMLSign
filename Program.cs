using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

try
{
    if (args.Length <= 3 || (args.Length == 1 && args[0] == "/?"))
    {
        Console.WriteLine("Uso CIE.XMLSign [file xml da firmare] [nome certificato] [nome store certificato] [scope certificato]");
        Console.WriteLine(" [file xml da firmare]: percorso completo del file xml da firmare");
        Console.WriteLine(" [nome certificato]: attributo CN del 'subject name' del certificato con cui cercarlo nello store");
        Console.WriteLine(" [store certificato]: \"AddressBook\"");
        Console.WriteLine("                      \"AuthRoot\"");
        Console.WriteLine("                      \"CertificateAuthority\"");
        Console.WriteLine("                      \"My\"");
        Console.WriteLine("                      \"Root\"");
        Console.WriteLine("                      \"TrustedPeople\"");
        Console.WriteLine("                      \"TrustedPublisher\"");
        Console.WriteLine(" [scope certificato]: \"LocalMachine\"");
        Console.WriteLine("                      \"CurrentUser\"");
        Console.WriteLine("");
        Console.WriteLine("Esempio");
        Console.WriteLine("Es. CIE.XMLSign \"test.xml\" \"test.dominio.it\" \"My\" \"CurrentUser\"");
        return 0;
    }

    StoreLocation sl;
    switch (args[3])
    {
        case "LocalMachine":
            sl = StoreLocation.LocalMachine;
            break;
        case "CurrentUser":
            sl = StoreLocation.CurrentUser;
            break;
        default:
            Console.WriteLine("ERRORE: Scope del certificato non valido");
            return 0;
    }

    StoreName st;
    switch (args[2])
    {
        case "My":
            st = StoreName.My;
            break;
        case "AddressBook":
            st = StoreName.AddressBook;
            break;
        case "AuthRoot":
            st = StoreName.AuthRoot;
            break;
        case "CertificateAuthority":
            st = StoreName.CertificateAuthority;
            break;
        case "Root":
            st = StoreName.Root;
            break;
        case "TrustedPeople":
            st = StoreName.TrustedPeople;
            break;
        case "TrustedPublisher":
            st = StoreName.TrustedPublisher;
            break;
        default:
            Console.WriteLine("ERRORE: Nome store certificato non valido");
            return 0;
    }

    var certificate = GetCertificateFromStore(sl, st, X509FindType.FindBySubjectName, args[1], false);
    if (certificate == null)
    {
        throw new Exception("ERRORE: il certificato non è stato trovato");
    }

    RSA? rsaKey = certificate.GetRSAPrivateKey();
    if (rsaKey == null)
    {
        throw new Exception("ERRORE: errore durante il reperimento della chiave privata del certificato");
    }

    // Create a new XML document.
    XmlDocument xmlDoc = new()
    {
        // Load an XML file into the XmlDocument object.
        PreserveWhitespace = true
    };
    xmlDoc.Load(args[0]);

    // Sign the XML document.
    SignXml(xmlDoc, rsaKey, certificate);

    // Save the document.
    xmlDoc.Save($"{args[0]}_signed.xml");

    Console.WriteLine("XML file signed.");
}
catch (Exception e)
{
    Console.WriteLine($"ERRORE: {e.Message}");
}

return -1;

static void SignXml(XmlDocument xmlDoc, RSA rsaKey, X509Certificate2 certificate)
{
    // Check arguments.
    if (xmlDoc == null)
        throw new ArgumentException(nameof(xmlDoc));
    if (rsaKey == null)
        throw new ArgumentException(nameof(rsaKey));

    // Create a SignedXml object.
    SignedXml signedXml = new(xmlDoc)
    {
        // Add the key to the SignedXml document.
        SigningKey = rsaKey
    };

    // Create a reference to be signed.
    Reference reference = new Reference
    {
        Uri = ""
    };

    // Add an enveloped transformation to the reference.
    XmlDsigEnvelopedSignatureTransform env = new();
    reference.AddTransform(env);

    // Add the reference to the SignedXml object.
    signedXml.AddReference(reference);

    KeyInfo keyInfo = new();
    keyInfo.AddClause(new KeyInfoX509Data(certificate));
    signedXml.KeyInfo = keyInfo;


    // Compute the signature.
    signedXml.ComputeSignature();

    // Get the XML representation of the signature and save
    // it to an XmlElement object.
    XmlElement xmlDigitalSignature = signedXml.GetXml();

    // Append the element to the XML document.
    //xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
    _ = xmlDoc.DocumentElement.InsertBefore(xmlDigitalSignature, xmlDoc.DocumentElement.ChildNodes[0]);
}

static X509Certificate2? GetCertificateFromStore(StoreLocation storeLocation, StoreName storeName, X509FindType findType, string findValue, bool validOnly)
{
    using X509Store store = new X509Store(storeName, storeLocation);
    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
    X509Certificate2Collection coll = store.Certificates.Find(findType, findValue, validOnly);

    X509Certificate2? certificate = null;
    if (coll.Count > 0)
    {
        certificate = coll[0];
    }

    return certificate;
}
