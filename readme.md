# CIE.XML Sign
L'utility serve a firmare il file xml metadata per i Service Provider conforme alle specifiche CIE/SPID.
Il certificato usato per firmare il file deve essere caricato nello storage di default "Personal" dell'utente corrente, il certificato deve contenere la chiave privata.

## Requisiti
- Visual Studio 2022
- .NET Core 6.0

## Utilizzo
CIE.XMLSign [percorso xml file] [nome certificato]

Il file xml firmato viene creato nella stessa cartella del file sorgente con il seguente nome "[nome file input]_signed.xml"

Es.
CIE.XMLSign.exe "c:\temp\metadata.xml" "example.com"