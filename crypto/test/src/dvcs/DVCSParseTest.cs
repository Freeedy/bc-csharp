using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using Org.BouncyCastle.asn1.dvcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
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
            throw new NotImplementedException();
        }



        [Test]
        public void Parse_dvcs_Test()
        {
            var dvcs = File.ReadAllBytes("data/dvcs/testdvcs");
            byte[] contentresult= default; 
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
    }
}
