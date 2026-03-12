using System;
using NUnit.Framework;
using Org.BouncyCastle.asn1.dvcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Tests.Dvcs
{
    [TestFixture]
    public class DVCSTimeTest
    {
        [Test]
        public void ToDateTime_WithGeneralizedTime_ReturnsCorrectDateTime()
        {
            // Arrange
            DateTime expected = new DateTime(2025, 6, 15, 10, 30, 45, DateTimeKind.Utc);
            var genTime = new DerGeneralizedTime(expected);
            var dvcsTime = new DVCSTime(genTime);

            // Act
            DateTime result = dvcsTime.ToDateTime();

            // Assert
            Assert.AreEqual(expected, result);
        }

        [Test]
        public void ToDateTime_WithDateTimeConstructor_ReturnsCorrectDateTime()
        {
            // Arrange
            DateTime expected = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var dvcsTime = new DVCSTime(expected);

            // Act
            DateTime result = dvcsTime.ToDateTime();

            // Assert
            Assert.AreEqual(expected, result);
        }

        [Test]
        public void ToDateTime_WithStringConstructor_ReturnsCorrectDateTime()
        {
            // Arrange — GeneralizedTime string format: YYYYMMDDHHmmSSZ
            var dvcsTime = new DVCSTime("20250615103045Z");

            // Act
            DateTime result = dvcsTime.ToDateTime();

            // Assert
            Assert.AreEqual(2025, result.Year);
            Assert.AreEqual(6, result.Month);
            Assert.AreEqual(15, result.Day);
            Assert.AreEqual(10, result.Hour);
            Assert.AreEqual(30, result.Minute);
            Assert.AreEqual(45, result.Second);
        }

        [Test]
        public void GetGenTime_WithGeneralizedTime_ReturnsNonNull()
        {
            // Arrange
            var genTime = new DerGeneralizedTime(DateTime.UtcNow);
            var dvcsTime = new DVCSTime(genTime);

            // Act & Assert
            Assert.IsNotNull(dvcsTime.GetGenTime());
            Assert.IsNull(dvcsTime.GetTimeStampToken());
        }

        [Test]
        public void GetTimeStampToken_WithContentInfo_ReturnsNonNull()
        {
            // Arrange
            var contentInfo = new ContentInfo(
                new DerObjectIdentifier("1.2.840.113549.1.7.2"),
                DerNull.Instance);
            var dvcsTime = new DVCSTime(contentInfo);

            // Act & Assert
            Assert.IsNull(dvcsTime.GetGenTime());
            Assert.IsNotNull(dvcsTime.GetTimeStampToken());
        }

        [Test]
        public void GetInstance_WithGeneralizedTime_ReturnsDVCSTime()
        {
            // Arrange
            var genTime = new DerGeneralizedTime(DateTime.UtcNow);

            // Act
            var dvcsTime = DVCSTime.GetInstance(genTime);

            // Assert
            Assert.IsNotNull(dvcsTime);
            Assert.IsNotNull(dvcsTime.GetGenTime());
            Assert.IsNull(dvcsTime.GetTimeStampToken());
        }

        [Test]
        public void ToDateTime_WithContentInfo_ThrowsWhenInvalidToken()
        {
            // Arrange — ContentInfo with invalid content cannot be parsed as TimeStampToken
            var contentInfo = new ContentInfo(
                new DerObjectIdentifier("1.2.840.113549.1.7.2"),
                DerNull.Instance);
            var dvcsTime = new DVCSTime(contentInfo);

            // Act & Assert — should throw because DerNull is not a valid CMS SignedData
            Assert.That(() => dvcsTime.ToDateTime(), Throws.Exception);
        }
    }
}
