# The Bouncy Castle Cryptography Library For .NET
[![NuGet](https://img.shields.io/nuget/dt/BouncyCastle.Cryptography.svg)](https://www.nuget.org/packages/BouncyCastle.Cryptography) [![NuGet](https://img.shields.io/nuget/vpre/BouncyCastle.Cryptography.svg)](https://www.nuget.org/packages/BouncyCastle.Cryptography)

The Bouncy Castle Cryptography library is a .NET implementation of cryptographic algorithms and protocols. It was developed by the Legion of the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this package, can be found at [https://www.bouncycastle.org](https://www.bouncycastle.org).

In addition to providing basic cryptography algorithms, the package also provides support for CMS, OpenPGP, (D)TLS, TSP, X.509 certificate generation and more. The package also includes implementations of the following NIST Post-Quantum Cryptography Standardization algorithms: CRYSTALS-Dilithium, CRYSTALS-Kyber, Falcon, SPHINCS+, Classic McEliece, FrodoKEM, NTRU, NTRU Prime, Picnic, Saber, BIKE, and SIKE. These should all be considered EXPERIMENTAL and subject to change or removal. SIKE in particular is already slated for removal and should be used for research purposes only.

The Legion also gratefully acknowledges the contributions made to this package by others (see [here](https://www.bouncycastle.org/csharp/contributors.html) for the current list). If you would like to contribute to our efforts please feel free to get in touch with us or visit our [donations page](https://www.bouncycastle.org/donate), sponsor some specific work, or purchase a [support contract](https://www.keyfactor.com/platform/bouncy-castle-support/).

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](https://www.bouncycastle.org/licence.html). This software includes a modified Bzip2 library, which is licensed under the [Apache Software License, Version 2.0](http://www.apache.org/licenses/). 

**Note**: This source tree is not the FIPS version of the APIs - if you are interested in our FIPS version please visit us [here](https://www.bouncycastle.org/fips-csharp) or contact us directly at [office@bouncycastle.org](mailto:office@bouncycastle.org).

## Installing BouncyCastle
You should install [BouncyCastle with NuGet:](https://www.nuget.org/packages/BouncyCastle.Cryptography)

    Install-Package BouncyCastle.Cryptography

Or via the .NET Core command line interface:

    dotnet add package BouncyCastle.Cryptography

Either commands, from Package Manager Console or .NET Core CLI, will download and install BouncyCastle.Cryptography.

## DVCS (RFC 3029) Support

This fork includes ASN.1 types and high-level builders for the Data Validation and Certification Server protocol defined in [RFC 3029](https://www.rfc-editor.org/rfc/rfc3029). Four service types are supported:

| Service | Enum | Description |
|---------|------|-------------|
| CPD | 1 | Certification of Possession of Data |
| VSD | 2 | Validation of Signed Document |
| VPKC | 3 | Validation of Public Key Certificates |
| CCPD | 4 | Certification of Claim of Possession of Data |

### Parsing a DVCS Response

A DVCS response is typically a CMS signed message wrapping a `DVCSResponse` ASN.1 structure. Extract the signed content first, then parse:

```csharp
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.asn1.dvcs;

byte[] rawDvcs = File.ReadAllBytes("response.dvcs");
CmsSignedData cms = new CmsSignedData(rawDvcs);

// Extract the encapsulated content bytes
CmsProcessableByteArray signedContent = (CmsProcessableByteArray)cms.SignedContent;
using MemoryStream ms = new MemoryStream();
signedContent.Write(ms);
byte[] contentBytes = ms.ToArray();

// Parse the DVCS response
DVCSResponse dvcsResponse = DVCSResponse.GetInstance(new Asn1InputStream(contentBytes).ReadObject());

// A response is either a DVCSCertInfo (success) or DVCSErrorNotice (failure)
if (dvcsResponse.CertInfo != null)
{
    DVCSCertInfo certInfo = dvcsResponse.CertInfo;
    // certInfo.SerialNumber, certInfo.MessageImprint, etc.
}
else
{
    DVCSErrorNotice error = dvcsResponse.ErrorNotice;
    // handle error
}
```

### Reading DVCSCertInfo Fields

Once you have a `DVCSCertInfo`, all RFC 3029 fields are available as properties. Optional fields return `null` when absent.

```csharp
DVCSCertInfo certInfo = dvcsResponse.CertInfo;

// Required fields — always present in a valid response
DVCSRequestInformation reqInfo = certInfo.DVReqInfo;
DigestInfo imprint = certInfo.MessageImprint;       // hash of the original data
DerInteger serial = certInfo.SerialNumber;

// Response time — use ToDateTime() to get a System.DateTime regardless
// of whether the server sent a GeneralizedTime or a TimeStampToken
DateTime when = certInfo.ResponseTime.ToDateTime();

// Optional fields — may be null
PkiStatusInfo status = certInfo.DvStatus;           // null if server omits it
PolicyInformation policy = certInfo.Policy;          // null if no policy
TargetEtcChain[] chains = certInfo.Certs;            // null if no cert chains
X509Extensions extensions = certInfo.Extensions;     // null if no extensions

// Request info details
int serviceType = reqInfo.Service.Value.IntValue;    // 1=CPD, 2=VSD, 3=VPKC, 4=CCPD
```

### Walking Certificate Chains

`DVCSCertInfo.Certs` returns an array of `TargetEtcChain`, one per validated certificate. Each chain has a target (usually a certificate) and optional validation tokens (PKI status, OCSP responses, CRLs).

```csharp
TargetEtcChain[] chains = certInfo.Certs;
if (chains == null) return; // no chains in this response

foreach (TargetEtcChain chain in chains)
{
    // Get the target certificate (null if the target is not a certificate token)
    X509CertificateStructure targetCert = chain.GetTargetCertificate();
    if (targetCert != null)
    {
        var cert = new X509Certificate(targetCert);
        // cert.SubjectDN, cert.IssuerDN, cert.NotAfter, etc.
    }

    // Shortcut helpers search the chain for common token types.
    // All return null when the token is not present — no exceptions.
    PkiStatusInfo pkiStatus = chain.GetChainPkiStatus();        // first PKIStatusInfo
    OcspResponse ocsp       = chain.GetChainOcspResponse();     // first OCSP response
    CertificateList crl     = chain.GetChainCrl();              // first CRL
    CertStatus certStatus   = chain.GetChainCertStatus();       // first OCSP CertStatus
    PathProcInput pathProc  = chain.GetPathProcInput();         // path processing input

    // For full control, iterate tokens directly:
    CertEtcToken[] tokens = chain.GetChain(); // null if no chain tokens
    if (tokens != null)
    {
        foreach (CertEtcToken token in tokens)
        {
            // Each typed accessor returns null for non-matching token types
            if (token.GetPkiStatus() != null) { /* ... */ }
            if (token.GetOcspResponse() != null) { /* ... */ }
            if (token.GetCrl() != null) { /* ... */ }
            if (token.GetCertificate() != null) { /* ... */ }
            if (token.GetOcspCertStatus() != null) { /* ... */ }
            if (token.GetOcspCertId() != null) { /* ... */ }
            if (token.GetEssCertId() != null) { /* ... */ }
            if (token.GetExtension() != null) { /* ... */ }
        }
    }
}
```

### Building a DVCS Request

Request builders exist for CPD, VSD, and CCPD. Each builder produces a `DVCSRequest` containing a `ContentInfo`.

```csharp
using Org.BouncyCastle.dvcs;

// CPD — certify that you possess this data
var cpdBuilder = new CPDRequestBuilder();
DVCSRequest cpdRequest = cpdBuilder.Build(dataBytes);

// VSD — validate a CMS signed document
var vsdBuilder = new VSDRequestBuilder();
DVCSRequest vsdRequest = vsdBuilder.Build(cmsSignedData);
```

Optional request parameters (nonce, requester, target DVCS server) are set on the builder before calling `Build`:

```csharp
var builder = new CPDRequestBuilder();
builder.SetNonce(BigInteger.ValueOf(12345));
builder.SetRequester(new GeneralName(GeneralName.Rfc822Name, "user@example.com"));
DVCSRequest request = builder.Build(dataBytes);
```

**Note:** `VPKCRequestBuilder` exists but has no `Build` method yet — VPKC request building is not implemented.

### Namespaces

| Namespace | Contains |
|-----------|----------|
| `Org.BouncyCastle.asn1.dvcs` | ASN.1 structures: `DVCSResponse`, `DVCSCertInfo`, `DVCSTime`, `CertEtcToken`, `TargetEtcChain`, `ServiceType`, etc. |
| `Org.BouncyCastle.dvcs` | High-level builders: `CPDRequestBuilder`, `VSDRequestBuilder`, `DVCSRequest`, `DVCSResponse` (CMS wrapper), etc. |

Note the two `DVCSResponse` classes: `Org.BouncyCastle.asn1.dvcs.DVCSResponse` is the raw ASN.1 CHOICE, while `Org.BouncyCastle.dvcs.DVCSResponse` is a convenience wrapper that accepts a `CmsSignedData` directly.

## Mailing Lists

For those who are interested, there are 2 mailing lists for participation in this project. To subscribe use the links below and include the word subscribe in the message body. (To unsubscribe, replace **subscribe** with **unsubscribe** in the message body)

*   [announce-crypto-csharp-request@bouncycastle.org](mailto:announce-crypto-csharp-request@bouncycastle.org)  
    This mailing list is for new release announcements only, general subscribers cannot post to it.
*   [dev-crypto-csharp-request@bouncycastle.org](mailto:dev-crypto-csharp-request@bouncycastle.org)  
    This mailing list is for discussion of development of the package. This includes bugs, comments, requests for enhancements, questions about use or operation.

**NOTE:** You need to be subscribed to send mail to the above mailing list.

## Feedback 

If you want to provide feedback directly to the members of **The Legion** then please use [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org). If you want to help this project survive please consider [donating](https://www.bouncycastle.org/donate).

For bug reporting/requests you can report issues on [github](https://github.com/bcgit/bc-csharp), or via [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org) if required. We will accept pull requests based on this repository as well, but only on the basis that any code included may be distributed under the [Bouncy Castle License](https://www.bouncycastle.org/licence.html).

## Finally

Enjoy!
