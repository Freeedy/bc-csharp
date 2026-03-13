using NUnit.Framework;
using Org.BouncyCastle.asn1.dvcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using CertStatus = Org.BouncyCastle.Asn1.Ocsp.CertStatus;

namespace Org.BouncyCastle.Tests.Dvcs
{
    [TestFixture]
    public class TargetEtcChainTest
    {
        private X509CertificateStructure CreateMinimalCertificate()
        {
            var serial = new DerInteger(1);
            var sigAlgId = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.11"));
            var issuer = new X509Name("CN=Test");
            var notBefore = new Time(new DerUtcTime("250101000000Z"));
            var notAfter = new Time(new DerUtcTime("260101000000Z"));
            var tbsSeq = new DerSequence(
                new DerTaggedObject(true, 0, new DerInteger(2)),
                serial,
                sigAlgId.ToAsn1Object(),
                issuer.ToAsn1Object(),
                new DerSequence(notBefore.ToAsn1Object(), notAfter.ToAsn1Object()),
                issuer.ToAsn1Object(),
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

        // =====================================================================
        // GetTargetCertificate tests
        // =====================================================================

        [Test]
        public void GetTargetCertificate_WhenTargetIsCertificate_ReturnsNonNull()
        {
            var cert = CreateMinimalCertificate();
            var certToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var chain = new TargetEtcChain(certToken);

            var result = chain.GetTargetCertificate();

            Assert.IsNotNull(result);
            Assert.AreSame(cert, result);
        }

        [Test]
        public void GetTargetCertificate_WhenTargetIsNotCertificate_ReturnsNull()
        {
            var pkiToken = new CertEtcToken(CertEtcToken.TAG_PKISTATUS, new PkiStatusInfo(0));
            var chain = new TargetEtcChain(pkiToken);

            var result = chain.GetTargetCertificate();

            Assert.IsNull(result);
        }

        // =====================================================================
        // GetChainPkiStatus tests
        // =====================================================================

        [Test]
        public void GetChainPkiStatus_WhenChainContainsPkiStatus_ReturnsNonNull()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var pkiStatus = new PkiStatusInfo(0);
            var pkiToken = new CertEtcToken(CertEtcToken.TAG_PKISTATUS, pkiStatus);
            var chain = new TargetEtcChain(targetToken, new CertEtcToken[] { pkiToken });

            var result = chain.GetChainPkiStatus();

            Assert.IsNotNull(result);
        }

        [Test]
        public void GetChainPkiStatus_WhenChainIsNull_ReturnsNull()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var chain = new TargetEtcChain(targetToken);

            var result = chain.GetChainPkiStatus();

            Assert.IsNull(result);
        }

        [Test]
        public void GetChainPkiStatus_WhenNoMatchingToken_ReturnsNull()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            // Chain with only a certificate token, no PKIStatusInfo
            var chainCertToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var chain = new TargetEtcChain(targetToken, new CertEtcToken[] { chainCertToken });

            var result = chain.GetChainPkiStatus();

            Assert.IsNull(result);
        }

        // =====================================================================
        // GetChainOcspResponse tests
        // =====================================================================

        [Test]
        public void GetChainOcspResponse_WhenChainContainsOcspResponse_ReturnsNonNull()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var ocspResp = new OcspResponse(new OcspResponseStatus(0), null);
            var ocspToken = new CertEtcToken(CertEtcToken.TAG_OCSPRESPONSE, ocspResp);
            var chain = new TargetEtcChain(targetToken, new CertEtcToken[] { ocspToken });

            var result = chain.GetChainOcspResponse();

            Assert.IsNotNull(result);
        }

        [Test]
        public void GetChainOcspResponse_WhenChainIsNull_ReturnsNull()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var chain = new TargetEtcChain(targetToken);

            var result = chain.GetChainOcspResponse();

            Assert.IsNull(result);
        }

        // =====================================================================
        // GetChainCrl tests
        // =====================================================================

        [Test]
        public void GetChainCrl_WhenChainContainsCrl_ReturnsNonNull()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var crl = CreateCertificateList();
            var crlToken = new CertEtcToken(CertEtcToken.TAG_CRL, crl);
            var chain = new TargetEtcChain(targetToken, new CertEtcToken[] { crlToken });

            var result = chain.GetChainCrl();

            Assert.IsNotNull(result);
        }

        [Test]
        public void GetChainCrl_WhenChainIsNull_ReturnsNull()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var chain = new TargetEtcChain(targetToken);

            var result = chain.GetChainCrl();

            Assert.IsNull(result);
        }

        // =====================================================================
        // GetChainCertStatus tests
        // =====================================================================

        [Test]
        public void GetChainCertStatus_WhenChainContainsCertStatus_ReturnsNonNull()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var certStatus = new CertStatus();
            var statusToken = new CertEtcToken(CertEtcToken.TAG_OCSPCERTSTATUS, certStatus);
            var chain = new TargetEtcChain(targetToken, new CertEtcToken[] { statusToken });

            var result = chain.GetChainCertStatus();

            Assert.IsNotNull(result);
        }

        [Test]
        public void GetChainCertStatus_WhenChainIsNull_ReturnsNull()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var chain = new TargetEtcChain(targetToken);

            var result = chain.GetChainCertStatus();

            Assert.IsNull(result);
        }

        [Test]
        public void GetChainCertStatus_WhenNoMatchingToken_ReturnsNull()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            // Chain with only PKIStatusInfo, no CertStatus
            var pkiToken = new CertEtcToken(CertEtcToken.TAG_PKISTATUS, new PkiStatusInfo(0));
            var chain = new TargetEtcChain(targetToken, new CertEtcToken[] { pkiToken });

            var result = chain.GetChainCertStatus();

            Assert.IsNull(result);
        }

        // =====================================================================
        // Existing methods not broken
        // =====================================================================

        [Test]
        public void GetTarget_StillWorksCorrectly()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var chain = new TargetEtcChain(targetToken);

            Assert.IsNotNull(chain.GetTarget());
            Assert.AreSame(targetToken, chain.GetTarget());
        }

        [Test]
        public void GetChain_StillWorksCorrectly()
        {
            var cert = CreateMinimalCertificate();
            var targetToken = new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert);
            var pkiToken = new CertEtcToken(CertEtcToken.TAG_PKISTATUS, new PkiStatusInfo(0));
            var chain = new TargetEtcChain(targetToken, new CertEtcToken[] { pkiToken });

            var tokens = chain.GetChain();

            Assert.IsNotNull(tokens);
            Assert.AreEqual(1, tokens.Length);
        }
    }
}
