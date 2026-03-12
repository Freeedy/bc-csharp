using System.Collections.Generic;
using NUnit.Framework;
using Org.BouncyCastle.asn1.dvcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Smime;
using Org.BouncyCastle.Asn1.X509;
using CertStatus = Org.BouncyCastle.Asn1.Ocsp.CertStatus;

namespace Org.BouncyCastle.Tests.Dvcs
{
    [TestFixture]
    public class CertEtcTokenTest
    {
        private X509CertificateStructure CreateMinimalCertificate()
        {
            // Build a minimal self-signed certificate structure via ASN.1
            var serial = new DerInteger(1);
            var sigAlgId = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.11")); // SHA256withRSA
            var issuer = new X509Name("CN=Test");
            var notBefore = new Time(new DerUtcTime("250101000000Z"));
            var notAfter = new Time(new DerUtcTime("260101000000Z"));
            var validity = new V3TbsCertificateGenerator();
            // Use raw ASN.1 sequence to build a minimal TBSCertificate and wrap it
            var tbsSeq = new DerSequence(
                new DerTaggedObject(true, 0, new DerInteger(2)), // version v3
                serial,
                sigAlgId.ToAsn1Object(),
                issuer.ToAsn1Object(),
                new DerSequence(notBefore.ToAsn1Object(), notAfter.ToAsn1Object()),
                issuer.ToAsn1Object(), // subject = issuer
                new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.1")),
                    new DerBitString(new byte[64])
                ).ToAsn1Object()
            );
            var certSeq = new DerSequence(
                tbsSeq,
                sigAlgId.ToAsn1Object(),
                new DerBitString(new byte[64])
            );
            return X509CertificateStructure.GetInstance(certSeq);
        }

        private PkiStatusInfo CreatePkiStatusInfo()
        {
            return new PkiStatusInfo(0); // granted
        }

        private EssCertID CreateEssCertId()
        {
            return new EssCertID(new byte[20]); // 20-byte hash
        }

        private ContentInfo CreateContentInfo()
        {
            return new ContentInfo(
                new DerObjectIdentifier("1.2.840.113549.1.7.1"), // id-data
                new DerOctetString(new byte[] { 1, 2, 3 })
            );
        }

        private CertificateList CreateCertificateList()
        {
            var sigAlgId = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.11"));
            var issuer = new X509Name("CN=CRLIssuer");
            var tbsCrl = new DerSequence(
                sigAlgId.ToAsn1Object(),
                issuer.ToAsn1Object(),
                new Time(new DerUtcTime("250101000000Z")).ToAsn1Object()
            );
            var crlSeq = new DerSequence(
                tbsCrl,
                sigAlgId.ToAsn1Object(),
                new DerBitString(new byte[32])
            );
            return CertificateList.GetInstance(crlSeq);
        }

        private CertStatus CreateCertStatus()
        {
            return new CertStatus(); // good (tag 0, implicit null)
        }

        private CertID CreateCertId()
        {
            return new CertID(
                new AlgorithmIdentifier(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1")), // SHA-256
                new DerOctetString(new byte[32]),
                new DerOctetString(new byte[32]),
                new DerInteger(1)
            );
        }

        private OcspResponse CreateOcspResponse()
        {
            return new OcspResponse(new OcspResponseStatus(0), null); // successful, no body
        }

        private SmimeCapabilities CreateSmimeCapabilities()
        {
            var capSeq = new DerSequence(
                new DerSequence(new DerObjectIdentifier("2.16.840.1.101.3.4.1.42")) // AES-256-CBC
            );
            return SmimeCapabilities.GetInstance(capSeq);
        }

        // =====================================================================
        // Tests: correct tag returns typed object
        // =====================================================================

        [Test]
        public void GetCertificate_CorrectTag_ReturnsNonNull()
        {
            var cert = CreateMinimalCertificate();
            var token = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);

            Assert.IsNotNull(token.GetCertificate());
            Assert.AreSame(cert, token.GetCertificate());
        }

        [Test]
        public void GetEssCertId_CorrectTag_ReturnsNonNull()
        {
            var essCertId = CreateEssCertId();
            var token = new CertEtcToken(CertEtcToken.TAG_ESSCERTID, essCertId);

            Assert.IsNotNull(token.GetEssCertId());
            Assert.AreSame(essCertId, token.GetEssCertId());
        }

        [Test]
        public void GetPkiStatus_CorrectTag_ReturnsNonNull()
        {
            var pkiStatus = CreatePkiStatusInfo();
            var token = new CertEtcToken(CertEtcToken.TAG_PKISTATUS, pkiStatus);

            Assert.IsNotNull(token.GetPkiStatus());
            Assert.AreSame(pkiStatus, token.GetPkiStatus());
        }

        [Test]
        public void GetAssertion_CorrectTag_ReturnsNonNull()
        {
            var contentInfo = CreateContentInfo();
            var token = new CertEtcToken(CertEtcToken.TAG_ASSERTION, contentInfo);

            Assert.IsNotNull(token.GetAssertion());
            Assert.AreSame(contentInfo, token.GetAssertion());
        }

        [Test]
        public void GetCrl_CorrectTag_ReturnsNonNull()
        {
            var crl = CreateCertificateList();
            var token = new CertEtcToken(CertEtcToken.TAG_CRL, crl);

            Assert.IsNotNull(token.GetCrl());
            Assert.AreSame(crl, token.GetCrl());
        }

        [Test]
        public void GetOcspCertStatus_CorrectTag_ReturnsNonNull()
        {
            var certStatus = CreateCertStatus();
            var token = new CertEtcToken(CertEtcToken.TAG_OCSPCERTSTATUS, certStatus);

            Assert.IsNotNull(token.GetOcspCertStatus());
            Assert.AreSame(certStatus, token.GetOcspCertStatus());
        }

        [Test]
        public void GetOcspCertId_CorrectTag_ReturnsNonNull()
        {
            var certId = CreateCertId();
            var token = new CertEtcToken(CertEtcToken.TAG_OCSPCERTID, certId);

            Assert.IsNotNull(token.GetOcspCertId());
            Assert.AreSame(certId, token.GetOcspCertId());
        }

        [Test]
        public void GetOcspResponse_CorrectTag_ReturnsNonNull()
        {
            var ocspResponse = CreateOcspResponse();
            var token = new CertEtcToken(CertEtcToken.TAG_OCSPRESPONSE, ocspResponse);

            Assert.IsNotNull(token.GetOcspResponse());
            Assert.AreSame(ocspResponse, token.GetOcspResponse());
        }

        [Test]
        public void GetCapabilities_CorrectTag_ReturnsNonNull()
        {
            var capabilities = CreateSmimeCapabilities();
            var token = new CertEtcToken(CertEtcToken.TAG_CAPABILITIES, capabilities);

            Assert.IsNotNull(token.GetCapabilities());
            Assert.AreSame(capabilities, token.GetCapabilities());
        }

        [Test]
        public void GetExtension_WithExtension_ReturnsNonNull()
        {
            // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN, extnValue OCTET STRING }
            var extValue = new DerOctetString(new BasicConstraints(true).GetEncoded());
            var extSeq = new DerSequence(
                X509Extensions.BasicConstraints,
                DerBoolean.True,
                extValue
            );
            var token = new CertEtcToken(extSeq);

            Assert.IsNotNull(token.GetExtension());
            Assert.IsTrue(token.GetExtension().IsCritical);
            Assert.AreEqual(extValue, token.GetExtension().Value);
            Assert.AreEqual(X509Extensions.BasicConstraints, token.GetExtensionOid());
        }

        // =====================================================================
        // Tests: wrong tag returns null for every accessor
        // =====================================================================

        [Test]
        public void GetCertificate_WrongTag_ReturnsNull()
        {
            var token = new CertEtcToken(CertEtcToken.TAG_PKISTATUS, CreatePkiStatusInfo());
            Assert.IsNull(token.GetCertificate());
        }

        [Test]
        public void GetEssCertId_WrongTag_ReturnsNull()
        {
            var token = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, CreateMinimalCertificate());
            Assert.IsNull(token.GetEssCertId());
        }

        [Test]
        public void GetPkiStatus_WrongTag_ReturnsNull()
        {
            var token = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, CreateMinimalCertificate());
            Assert.IsNull(token.GetPkiStatus());
        }

        [Test]
        public void GetAssertion_WrongTag_ReturnsNull()
        {
            var token = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, CreateMinimalCertificate());
            Assert.IsNull(token.GetAssertion());
        }

        [Test]
        public void GetCrl_WrongTag_ReturnsNull()
        {
            var token = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, CreateMinimalCertificate());
            Assert.IsNull(token.GetCrl());
        }

        [Test]
        public void GetOcspCertStatus_WrongTag_ReturnsNull()
        {
            var token = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, CreateMinimalCertificate());
            Assert.IsNull(token.GetOcspCertStatus());
        }

        [Test]
        public void GetOcspCertId_WrongTag_ReturnsNull()
        {
            var token = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, CreateMinimalCertificate());
            Assert.IsNull(token.GetOcspCertId());
        }

        [Test]
        public void GetOcspResponse_WrongTag_ReturnsNull()
        {
            var token = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, CreateMinimalCertificate());
            Assert.IsNull(token.GetOcspResponse());
        }

        [Test]
        public void GetCapabilities_WrongTag_ReturnsNull()
        {
            var token = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, CreateMinimalCertificate());
            Assert.IsNull(token.GetCapabilities());
        }

        [Test]
        public void GetExtension_WhenNotExtensionToken_ReturnsNull()
        {
            var token = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, CreateMinimalCertificate());
            Assert.IsNull(token.GetExtension());
        }

        // =====================================================================
        // Cross-check: each accessor null for every other tag
        // =====================================================================

        [Test]
        public void AllAccessors_WrongTag_ReturnNull()
        {
            // Create a token with TAG_ESSCERTID
            var token = new CertEtcToken(CertEtcToken.TAG_ESSCERTID, CreateEssCertId());

            Assert.IsNull(token.GetCertificate(), "GetCertificate should be null for TAG_ESSCERTID");
            Assert.IsNotNull(token.GetEssCertId(), "GetEssCertId should be non-null for TAG_ESSCERTID");
            Assert.IsNull(token.GetPkiStatus(), "GetPkiStatus should be null for TAG_ESSCERTID");
            Assert.IsNull(token.GetAssertion(), "GetAssertion should be null for TAG_ESSCERTID");
            Assert.IsNull(token.GetCrl(), "GetCrl should be null for TAG_ESSCERTID");
            Assert.IsNull(token.GetOcspCertStatus(), "GetOcspCertStatus should be null for TAG_ESSCERTID");
            Assert.IsNull(token.GetOcspCertId(), "GetOcspCertId should be null for TAG_ESSCERTID");
            Assert.IsNull(token.GetOcspResponse(), "GetOcspResponse should be null for TAG_ESSCERTID");
            Assert.IsNull(token.GetCapabilities(), "GetCapabilities should be null for TAG_ESSCERTID");
            Assert.IsNull(token.GetExtension(), "GetExtension should be null for TAG_ESSCERTID");
        }
    }
}
