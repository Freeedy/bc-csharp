using System;

namespace Org.BouncyCastle.Asn1.X509
{
    public class AlgorithmIdentifier
        : Asn1Encodable
    {
        private readonly DerObjectIdentifier	algorithm;
        private readonly Asn1Encodable			parameters;

        public static AlgorithmIdentifier GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AlgorithmIdentifier algorithmIdentifier)
                return algorithmIdentifier;
            return new AlgorithmIdentifier(Asn1Sequence.GetInstance(obj));
        }

        public static AlgorithmIdentifier GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new AlgorithmIdentifier(Asn1Sequence.GetInstance(obj, explicitly));

        public static AlgorithmIdentifier GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is AlgorithmIdentifier algorithmIdentifier)
                return algorithmIdentifier;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new AlgorithmIdentifier(asn1Sequence);

            return null;
        }

        public static AlgorithmIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AlgorithmIdentifier(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public AlgorithmIdentifier(
            DerObjectIdentifier algorithm)
        {
            this.algorithm = algorithm;
        }

        public AlgorithmIdentifier(
            DerObjectIdentifier algorithm,
            Asn1Encodable		parameters)
        {
            this.algorithm = algorithm;
            this.parameters = parameters;
        }

        internal AlgorithmIdentifier(
            Asn1Sequence seq)
        {
            if (seq.Count < 1 || seq.Count > 2)
                throw new ArgumentException("Bad sequence size: " + seq.Count);

            this.algorithm = DerObjectIdentifier.GetInstance(seq[0]);
            this.parameters = seq.Count < 2 ? null : seq[1];
        }

        /// <summary>
        /// Return the OID in the Algorithm entry of this identifier.
        /// </summary>
		public virtual DerObjectIdentifier Algorithm
		{
			get { return algorithm; }
		}

        /// <summary>
        /// Return the parameters structure in the Parameters entry of this identifier.
        /// </summary>
        public virtual Asn1Encodable Parameters
        {
            get { return parameters; }
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *      AlgorithmIdentifier ::= Sequence {
         *                            algorithm OBJECT IDENTIFIER,
         *                            parameters ANY DEFINED BY algorithm OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(algorithm);
            v.AddOptional(parameters);
            return new DerSequence(v);
        }
    }
}
