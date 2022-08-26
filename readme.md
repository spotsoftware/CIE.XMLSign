# CIE.XMLSign
L'utility serve a firmare il file xml metadata per i Service Provider conforme alle specifiche CIE/SPID.
Il certificato usato per firmare il file deve essere caricato nello store di Windows e deve contenere la chiave privata.

## Requisiti
- Visual Studio 2022
- .NET Core 6.0

## Utilizzo
Uso CIE.XMLSign [file xml da firmare] [nome certificato] [nome store certificato] [scope certificato]

    [file xml da firmare]: percorso completo del file xml da firmare
    
    [nome certificato]: attributo CN del 'subject name' del certificato con cui cercarlo nello store
    
    [store certificato]: "AddressBook"
                        "AuthRoot"
                        "CertificateAuthority"
                        "My"
                        "Root"
                        "TrustedPeople"
                        "TrustedPublisher"
                        
    [scope certificato]: "LocalMachine"
                        "CurrentUser"

Il file xml firmato viene creato nella stessa cartella del file sorgente con il seguente nome "[nome file input]_signed.xml"

Esempio

CIE.XMLSign "test.xml" "test.dominio.it" "My" "CurrentUser"
