using System;
using System.IO;
using System.Linq;
using NUnit.Framework;
using Org.BouncyCastle.asn1.dvcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.src.dvcs
{
    [TestFixture]
    public class DVCSParseTest : SimpleTest
    {
        public override string Name
        {
            get
            {
                return "Dvcs parsing test";
            }
        }

        public override void PerformTest()
        {
            // NUnit [Test] methods handle testing; nothing needed here.
        }

        private DVCSResponse LoadTestDvcsResponse()
        {
            var dvcs = File.ReadAllBytes("data/dvcs/testdvcs");
            CmsSignedData cms = new CmsSignedData(dvcs);
            CmsProcessableByteArray signedContent = (CmsProcessableByteArray)cms.SignedContent;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                signedContent.Write(memoryStream);
                var contentresult = memoryStream.ToArray();
                Asn1InputStream asn1st = new Asn1InputStream(contentresult);
                return DVCSResponse.GetInstance(asn1st.ReadObject());
            }
        }



        [Test]
        public void Parse_dvcs_old_Test()
        {
            var dvcs = File.ReadAllBytes("data/dvcs/testdvcs");
            byte[] contentresult = default;
            try
            {
                CmsSignedData cms = new CmsSignedData(dvcs);

                CmsProcessableByteArray signedContent = (CmsProcessableByteArray)cms.SignedContent;

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    signedContent.Write(memoryStream);
                    contentresult = memoryStream.ToArray();


                }

            }
            catch (Exception e)
            {

            }


            Asn1InputStream asn1st = new Asn1InputStream(contentresult);
            var responseObject = asn1st.ReadObject();

            DVCSResponse dvcsResponse = DVCSResponse.GetInstance(responseObject);
            DVCSCertInfo dvcsCertInfo = dvcsResponse.CertInfo;
            TargetEtcChain[] etcChains = dvcsCertInfo.Certs;

            var time = dvcsResponse.CertInfo.ResponseTime.GetGenTime().ToDateTime();



            if (etcChains != null)
            {
                foreach (TargetEtcChain chain in etcChains)
                {
                    CertEtcToken[] tokens = chain.GetChain();
                    var target = chain.GetTarget();

                    if (target.TagNo == 0) // Type 0 indicates the certificate token
                    {
                        var certObject = target.Value.ToAsn1Object();

                        if (certObject is Asn1Sequence certStructObject)
                        {
                            // Parse the certificate
                            X509CertificateStructure certStruct =
                                X509CertificateStructure.GetInstance(certStructObject);
                            X509Certificate cert = new X509Certificate(certStruct);
                            var status = tokens.Where(x => x.TagNo == 2).FirstOrDefault();
                            var statusinfo = PkiStatusInfo.GetInstance(status.Value.ToAsn1Object());


                        }

                    }

                }
            }

            Assert.IsNotNull(dvcsResponse);

        }


        [Test]
        public void Parse_dvcs_Test()
        {
            var dvcs = File.ReadAllBytes("data/dvcs/testdvcs");
            byte[] contentresult;

            CmsSignedData cms = new CmsSignedData(dvcs);
            CmsProcessableByteArray signedContent = (CmsProcessableByteArray)cms.SignedContent;

            using (MemoryStream memoryStream = new MemoryStream())
            {
                signedContent.Write(memoryStream);
                contentresult = memoryStream.ToArray();
            }

            Asn1InputStream asn1st = new Asn1InputStream(contentresult);
            var responseObject = asn1st.ReadObject();

            DVCSResponse dvcsResponse = DVCSResponse.GetInstance(responseObject);
            Assert.IsNotNull(dvcsResponse);
            Assert.IsNotNull(dvcsResponse.CertInfo);

            DVCSCertInfo dvcsCertInfo = dvcsResponse.CertInfo;
            Assert.IsNotNull(dvcsCertInfo.MessageImprint);
            Assert.IsNotNull(dvcsCertInfo.SerialNumber);
            Assert.IsNotNull(dvcsCertInfo.ResponseTime);

            var time = dvcsCertInfo.ResponseTime.ToDateTime();
            Assert.IsTrue(time > DateTime.MinValue);

            TargetEtcChain[] etcChains = dvcsCertInfo.Certs;

            if (etcChains != null)
            {
                foreach (TargetEtcChain chain in etcChains)
                {
                    var target = chain.GetTarget();
                    Assert.IsNotNull(target);

                    // Target certificate check (R2T3 helper)
                    var targetCert = chain.GetTargetCertificate();
                    if (targetCert != null)
                    {
                        X509Certificate cert = new X509Certificate(targetCert);
                        Assert.IsNotNull(cert.SubjectDN);
                    }

                    // Chain PKI status check (R2T3 helper)
                    var pkiStatus = chain.GetChainPkiStatus();
                    // pkiStatus may be null — some servers don't send it, should not crash
                }
            }

            Assert.IsNotNull(dvcsResponse);
        }

        [Test]
        public void Parse_CmsSignedData_Layer()
        {
            var dvcs = File.ReadAllBytes("data/dvcs/testdvcs");
            CmsSignedData cms = new CmsSignedData(dvcs);

            // SignedContent must not be null
            Assert.IsNotNull(cms.SignedContent, "CMS SignedContent should not be null");
            Console.WriteLine("SignedContent: present");

            // ContentInfo must exist
            Assert.IsNotNull(cms.ContentInfo, "CMS ContentInfo should not be null");
            Console.WriteLine($"ContentInfo ContentType: {cms.ContentInfo.ContentType}");

            // Signer count > 0
            var signerInfos = cms.GetSignerInfos();
            Assert.IsNotNull(signerInfos, "SignerInfos should not be null");
            var signers = signerInfos.GetSigners();
            Assert.IsNotNull(signers, "Signers collection should not be null");
            int signerCount = 0;
            foreach (var signer in signers)
            {
                signerCount++;
            }
            Assert.IsTrue(signerCount > 0, "Signer count should be > 0");
            Console.WriteLine($"Signer count: {signerCount}");

            // CMS certificates collection
            var certs = cms.GetCertificates();
            Assert.IsNotNull(certs, "CMS certificates collection should not be null");
            var allCerts = certs.EnumerateMatches(null);
            int certCount = 0;
            foreach (var c in allCerts)
            {
                certCount++;
                if (c is X509Certificate x509)
                {
                    Console.WriteLine($"  CMS Certificate Subject: {x509.SubjectDN}");
                    Console.WriteLine($"  CMS Certificate Issuer: {x509.IssuerDN}");
                }
            }
            Console.WriteLine($"CMS Certificates count: {certCount}");
        }

        [Test]
        public void Parse_DVCSResponse_Structure()
        {
            DVCSResponse dvcsResponse = LoadTestDvcsResponse();

            // CertInfo must not be null (successful response)
            Assert.IsNotNull(dvcsResponse.CertInfo, "DVCSResponse.CertInfo should not be null (successful response)");
            Console.WriteLine("CertInfo: present");

            // ErrorNotice must be null (no error)
            Assert.IsNull(dvcsResponse.ErrorNotice, "DVCSResponse.ErrorNotice should be null (no error)");
            Console.WriteLine("ErrorNotice: null (no error)");
        }

        [Test]
        public void Parse_DVCSCertInfo_AllFields()
        {
            DVCSResponse dvcsResponse = LoadTestDvcsResponse();
            DVCSCertInfo certInfo = dvcsResponse.CertInfo;
            Assert.IsNotNull(certInfo, "DVCSCertInfo should not be null");

            // Version
            Console.WriteLine($"Version: {certInfo.Version}");
            Assert.IsTrue(certInfo.Version >= 1, "Version should be >= 1");

            // DVReqInfo
            Assert.IsNotNull(certInfo.DVReqInfo, "DVReqInfo should not be null");
            Console.WriteLine($"DVReqInfo: present");

            // MessageImprint
            Assert.IsNotNull(certInfo.MessageImprint, "MessageImprint should not be null");
            byte[] digest = certInfo.MessageImprint.GetDigest();
            Assert.IsNotNull(digest, "MessageImprint digest should not be null");
            Assert.IsTrue(digest.Length > 0, "MessageImprint digest should be non-empty");
            Console.WriteLine($"MessageImprint AlgorithmID: {certInfo.MessageImprint.AlgorithmID.Algorithm.Id}");
            Console.WriteLine($"MessageImprint Digest length: {digest.Length}");

            // SerialNumber
            Assert.IsNotNull(certInfo.SerialNumber, "SerialNumber should not be null");
            Assert.IsTrue(certInfo.SerialNumber.Value.SignValue > 0, "SerialNumber should be > 0");
            Console.WriteLine($"SerialNumber: {certInfo.SerialNumber}");

            // ResponseTime
            Assert.IsNotNull(certInfo.ResponseTime, "ResponseTime should not be null");
            DateTime responseDateTime = certInfo.ResponseTime.ToDateTime();
            Assert.IsTrue(responseDateTime > DateTime.MinValue, "ResponseTime should be a valid DateTime");
            Console.WriteLine($"ResponseTime: {responseDateTime}");

            // DvStatus (optional)
            PkiStatusInfo dvStatus = certInfo.DvStatus;
            if (dvStatus != null)
            {
                Console.WriteLine($"DvStatus: {dvStatus.Status}");
            }
            else
            {
                Console.WriteLine("DvStatus: null (not present)");
            }

            // Policy (optional)
            PolicyInformation policy = certInfo.Policy;
            if (policy != null)
            {
                Console.WriteLine($"Policy PolicyIdentifier: {policy.PolicyIdentifier}");
            }
            else
            {
                Console.WriteLine("Policy: null (not present)");
            }

            // RequestSignature (optional)
            Asn1Set reqSignature = certInfo.RequestSignature;
            if (reqSignature != null)
            {
                Console.WriteLine($"RequestSignature count: {reqSignature.Count}");
            }
            else
            {
                Console.WriteLine("RequestSignature: null (not present)");
            }

            // Certs (optional)
            TargetEtcChain[] certs = certInfo.Certs;
            if (certs != null)
            {
                Assert.IsTrue(certs.Length > 0, "Certs array should have length > 0");
                Console.WriteLine($"Certs count: {certs.Length}");
            }
            else
            {
                Console.WriteLine("Certs: null (not present)");
            }

            // Extensions (optional)
            X509Extensions extensions = certInfo.Extensions;
            if (extensions != null)
            {
                Console.WriteLine($"Extensions: present");
            }
            else
            {
                Console.WriteLine("Extensions: null (not present)");
            }
        }

        [Test]
        public void Parse_DVCSRequestInformation_AllFields()
        {
            DVCSResponse dvcsResponse = LoadTestDvcsResponse();
            DVCSCertInfo certInfo = dvcsResponse.CertInfo;
            DVCSRequestInformation reqInfo = certInfo.DVReqInfo;
            Assert.IsNotNull(reqInfo, "DVCSRequestInformation should not be null");

            // Version
            Console.WriteLine($"Version: {reqInfo.Version}");
            Assert.IsTrue(reqInfo.Version >= 1, "Version should be >= 1");

            // Service
            ServiceType service = reqInfo.Service;
            Assert.IsNotNull(service, "Service should not be null");
            int serviceValue = service.Value.IntValue;
            Console.WriteLine($"Service: {service} (value={serviceValue})");
            // ServiceType: CPD=1, VSD=2, VPKC=3, CCPD=4
            Assert.IsTrue(serviceValue >= 1 && serviceValue <= 4,
                "Service value should be between 1 and 4 (CPD=1, VSD=2, VPKC=3, CCPD=4)");

            // Nonce (optional)
            var nonce = reqInfo.Nonce;
            if (nonce != null)
            {
                Console.WriteLine($"Nonce: {nonce}");
            }
            else
            {
                Console.WriteLine("Nonce: null (not present)");
            }

            // RequestTime (optional)
            DVCSTime requestTime = reqInfo.RequestTime;
            if (requestTime != null)
            {
                Console.WriteLine($"RequestTime: {requestTime.ToDateTime()}");
            }
            else
            {
                Console.WriteLine("RequestTime: null (not present)");
            }

            // Requester (optional)
            GeneralNames requester = reqInfo.Requester;
            if (requester != null)
            {
                Console.WriteLine($"Requester: {requester}");
            }
            else
            {
                Console.WriteLine("Requester: null (not present)");
            }

            // RequestPolicy (optional)
            PolicyInformation requestPolicy = reqInfo.RequestPolicy;
            if (requestPolicy != null)
            {
                Console.WriteLine($"RequestPolicy: {requestPolicy.PolicyIdentifier}");
            }
            else
            {
                Console.WriteLine("RequestPolicy: null (not present)");
            }

            // DVCS GeneralNames (optional)
            GeneralNames dvcsNames = reqInfo.DVCS;
            if (dvcsNames != null)
            {
                Console.WriteLine($"DVCS: {dvcsNames}");
            }
            else
            {
                Console.WriteLine("DVCS: null (not present)");
            }

            // DataLocations (optional)
            GeneralNames dataLocations = reqInfo.DataLocations;
            if (dataLocations != null)
            {
                Console.WriteLine($"DataLocations: {dataLocations}");
            }
            else
            {
                Console.WriteLine("DataLocations: null (not present)");
            }

            // Extensions (optional)
            X509Extensions extensions = reqInfo.Extensions;
            if (extensions != null)
            {
                Console.WriteLine($"Extensions: present");
            }
            else
            {
                Console.WriteLine("Extensions: null (not present)");
            }
        }

        [Test]
        public void Parse_MessageImprint_Details()
        {
            DVCSResponse dvcsResponse = LoadTestDvcsResponse();
            DVCSCertInfo certInfo = dvcsResponse.CertInfo;
            DigestInfo messageImprint = certInfo.MessageImprint;
            Assert.IsNotNull(messageImprint, "MessageImprint should not be null");

            // AlgorithmID
            AlgorithmIdentifier algId = messageImprint.AlgorithmID;
            Assert.IsNotNull(algId, "AlgorithmID should not be null");
            Assert.IsNotNull(algId.Algorithm, "Algorithm OID should not be null");
            string algorithmOid = algId.Algorithm.Id;
            Assert.IsNotNull(algorithmOid, "Algorithm OID string should not be null");
            Console.WriteLine($"AlgorithmID OID: {algorithmOid}");

            // Known OIDs for reference
            if (algorithmOid == "2.16.840.1.101.3.4.2.1")
                Console.WriteLine("  Algorithm: SHA-256");
            else if (algorithmOid == "2.16.840.1.101.3.4.2.2")
                Console.WriteLine("  Algorithm: SHA-384");
            else if (algorithmOid == "2.16.840.1.101.3.4.2.3")
                Console.WriteLine("  Algorithm: SHA-512");
            else if (algorithmOid == "1.3.14.3.2.26")
                Console.WriteLine("  Algorithm: SHA-1");
            else
                Console.WriteLine($"  Algorithm: unknown OID ({algorithmOid})");

            // AlgorithmID parameters (may be null for some algorithms)
            Asn1Encodable algParams = algId.Parameters;
            Console.WriteLine($"AlgorithmID Parameters: {(algParams != null ? algParams.ToString() : "null")}");

            // Digest
            byte[] digest = messageImprint.GetDigest();
            Assert.IsNotNull(digest, "Digest should not be null");
            Assert.IsTrue(digest.Length > 0, "Digest length should be > 0");
            Console.WriteLine($"Digest length: {digest.Length} bytes");
            Console.WriteLine($"Digest hex: {Hex.ToHexString(digest)}");
        }

        [Test]
        public void Parse_TargetEtcChains_AllTokens()
        {
            DVCSResponse dvcsResponse = LoadTestDvcsResponse();
            DVCSCertInfo certInfo = dvcsResponse.CertInfo;

            TargetEtcChain[] etcChains = certInfo.Certs;
            if (etcChains == null)
            {
                Console.WriteLine("Certs: null (no TargetEtcChain present in this response)");
                Assert.Inconclusive("No TargetEtcChain present in the test DVCS response");
                return;
            }

            Assert.IsTrue(etcChains.Length > 0, "TargetEtcChain array should not be empty");
            Console.WriteLine($"Chain count: {etcChains.Length}");

            for (int i = 0; i < etcChains.Length; i++)
            {
                Console.WriteLine($"--- Chain [{i}] ---");
                var chain = etcChains[i];
                Assert.IsNotNull(chain, $"Chain[{i}] should not be null");

                var target = chain.GetTarget();
                Assert.IsNotNull(target, $"Chain[{i}] target should not be null");
                Console.WriteLine($"  Target TagNo: {target.TagNo}");

                var cert = chain.GetTargetCertificate();
                if (cert != null)
                {
                    var x509 = new X509Certificate(cert);
                    Console.WriteLine($"  Certificate Subject: {x509.SubjectDN}");
                    Console.WriteLine($"  Certificate Issuer: {x509.IssuerDN}");
                    Console.WriteLine($"  Certificate Serial: {x509.SerialNumber}");
                    Console.WriteLine($"  Certificate NotBefore: {x509.NotBefore}");
                    Console.WriteLine($"  Certificate NotAfter: {x509.NotAfter}");
                }
                else
                {
                    Console.WriteLine($"  TargetCertificate: null (target is not a certificate token)");
                }

                CertEtcToken[] tokens = chain.GetChain();

                if (tokens != null)
                {
                    Console.WriteLine($"  Chain tokens count: {tokens.Length}");
                    foreach (var token in tokens)
                    {
                        Console.WriteLine($"    Token TagNo: {token.TagNo}");
                        // Check each token type
                        if (token.GetPkiStatus() != null)
                            Console.WriteLine($"    PKIStatus: {token.GetPkiStatus().Status}");
                        if (token.GetOcspResponse() != null)
                            Console.WriteLine($"    OCSPResponse: present");
                        if (token.GetCrl() != null)
                            Console.WriteLine($"    CRL: present");
                        if (token.GetCertificate() != null)
                        {
                            var tokenCert = new X509Certificate(token.GetCertificate());
                            Console.WriteLine($"    Certificate: {tokenCert.SubjectDN}");
                        }
                        if (token.GetOcspCertStatus() != null)
                            Console.WriteLine($"    CertStatus: present");
                        if (token.GetOcspCertId() != null)
                            Console.WriteLine($"    CertID: present");
                        if (token.GetEssCertId() != null)
                            Console.WriteLine($"    ESSCertID: present");
                        if (token.GetAssertion() != null)
                            Console.WriteLine($"    Assertion: present");
                        if (token.GetCapabilities() != null)
                            Console.WriteLine($"    SMIMECapabilities: present");
                        if (token.GetExtension() != null)
                            Console.WriteLine($"    Extension: present");
                    }
                }
                else
                {
                    Console.WriteLine($"  Chain: null or unparseable (no typed validation tokens)");
                }

                var status = chain.GetChainPkiStatus();
                Console.WriteLine($"  ChainPkiStatus: {(status != null ? status.Status.ToString() : "null")}");

                var ocspResp = chain.GetChainOcspResponse();
                Console.WriteLine($"  ChainOcspResponse: {(ocspResp != null ? "present" : "null")}");

                var crl = chain.GetChainCrl();
                Console.WriteLine($"  ChainCrl: {(crl != null ? "present" : "null")}");

                var certStatus = chain.GetChainCertStatus();
                Console.WriteLine($"  ChainCertStatus: {(certStatus != null ? "present" : "null")}");

                var pathProc = chain.GetPathProcInput();
                Console.WriteLine($"  PathProcInput: {(pathProc != null ? "present" : "null")}");
            }
        }

        [Test]
        public void Parse_ResponseTime_Details()
        {
            DVCSResponse dvcsResponse = LoadTestDvcsResponse();
            DVCSCertInfo certInfo = dvcsResponse.CertInfo;
            DVCSTime responseTime = certInfo.ResponseTime;
            Assert.IsNotNull(responseTime, "ResponseTime should not be null");

            // Check which CHOICE variant is used
            var genTime = responseTime.GetGenTime();
            var timeStampToken = responseTime.GetTimeStampToken();

            if (genTime != null)
            {
                Console.WriteLine("ResponseTime CHOICE: GeneralizedTime");
                Console.WriteLine($"  GenTime raw: {genTime}");
                Console.WriteLine($"  GenTime DateTime: {genTime.ToDateTime()}");
                Assert.IsNull(timeStampToken, "TimeStampToken should be null when GenTime is used");
            }
            else if (timeStampToken != null)
            {
                Console.WriteLine("ResponseTime CHOICE: TimeStampToken (ContentInfo)");
                Console.WriteLine($"  TimeStampToken ContentType: {timeStampToken.ContentType}");
                Assert.IsNull(genTime, "GenTime should be null when TimeStampToken is used");
            }
            else
            {
                Assert.Fail("Both GenTime and TimeStampToken are null - invalid DVCSTime");
            }

            // ToDateTime() must always work regardless of CHOICE
            DateTime dateTime = responseTime.ToDateTime();
            Assert.IsTrue(dateTime > DateTime.MinValue, "ToDateTime() should return a valid DateTime");
            Assert.IsTrue(dateTime < DateTime.MaxValue, "ToDateTime() should return a valid DateTime");
            Console.WriteLine($"  ToDateTime(): {dateTime}");
            Console.WriteLine($"  ToDateTime() Kind: {dateTime.Kind}");
        }
    }
}
