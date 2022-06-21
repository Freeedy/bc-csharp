using System;

namespace Org.BouncyCastle.Security.Certificates
{
#if !PORTABLE
    [Serializable]
#endif
    public class CrlException : GeneralSecurityException
	{
		public CrlException() : base() { }
		public CrlException(string msg) : base(msg) {}
		public CrlException(string msg, Exception e) : base(msg, e) {}
	}
}
