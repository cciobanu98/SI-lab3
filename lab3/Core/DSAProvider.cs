using DJD.Security;
using lab3.Abstract;
using lab3.Models;
using System;
using System.Security.Cryptography;

namespace lab3.Core
{
    public class DSAProvider : IDSAProvider
    {
        int confidence = 20;
        BigInteger q;
        BigInteger p;
        BigInteger g;
        BigInteger y;
        BigInteger x;
        BigInteger k;
        readonly Random rand;

        public DSAProvider()
        {
            rand = new Random();
        }

        public DSAInfo GenerateKey()
        {
            q = BigInteger.genPseudoPrime(160, confidence, rand);
            p = GenerateP(q, 512);
            g = GenerateG(p, q);
            y = GenerateY(p, q);
            return new DSAInfo()
            {
                G = G.ToString(),
                Y = Y.ToString(),
                P = P.ToString(),
                Q = Q.ToString(),
                X = X.ToString(),
            };
        }

        public Tuple<BigInteger, BigInteger> SignData(byte[] data)
        {
            var r = GenerateR();
            var s = GenerateS(r, data);

            return new Tuple<BigInteger, BigInteger>(r, s);
        }

        public bool Verify(byte[] data, BigInteger r, BigInteger s)
        {
            if (r <= 0 || r >= q)
            {
                return false;
            }
            if (s <= 0 || s >= q)
            {
                return false;
            }

            SHA1 sha1 = SHA1.Create();
            BigInteger hash = new BigInteger(sha1.ComputeHash(data));
            BigInteger w = s.modInverse(q);
            BigInteger u1 = (hash * w) % q;
            BigInteger u2 = (r * w) % q;
            BigInteger v = ((g.modPow(u1, p) * y.modPow(u2, p)) % p) % q;
            return v == r;
        }

        public BigInteger Q => q;
        public BigInteger P => p;
        public BigInteger G => g;
        public BigInteger Y => y;
        public BigInteger X => x;

        private BigInteger GenerateP(BigInteger q, int l)
        {
            if (l % 64 != 0)
            {
                throw new ArgumentException("L value is wrong");
            }
            BigInteger pTemp;
            BigInteger pTemp2;
            do
            {
                pTemp = BigInteger.genPseudoPrime(l, confidence, rand);
                pTemp2 = pTemp - 1;
                pTemp -= (pTemp2 % q);
            } while (!pTemp.isProbablePrime(confidence) || pTemp.bitCount() != l);
            return pTemp;
        }

        private BigInteger GenerateG(BigInteger p, BigInteger q)
        {
            var aux = p - 1;
            var pow = aux / q;
            BigInteger gTemp;
            do
            {
                gTemp = BigInteger.genPseudoPrime(aux.bitCount(), confidence, rand);
            } while (gTemp >= aux && gTemp <= 1);

            return gTemp.modPow(pow, p);
        }

        private BigInteger GenerateY(BigInteger p, BigInteger q)
        {
            do
            {
                x = BigInteger.genPseudoPrime(q.bitCount(), confidence, rand);
            } while (x <= 0 && x >= q);
            return g.modPow(x, p);
        }

        private BigInteger GenerateR()
        {
            k = GenerateK(q);
            return (g.modPow(k, p) % q);
        }

        private BigInteger GenerateK(BigInteger q)
        {
            BigInteger tempK;
            do
            {
                tempK = BigInteger.genPseudoPrime(q.bitCount(), confidence, rand);
            } while (tempK >= q && tempK <= 0);
            return tempK;
        }

        private BigInteger GenerateS(BigInteger r, byte[] data)
        {
            SHA1 sha1 = SHA1.Create();

            BigInteger hash = new BigInteger(sha1.ComputeHash(data));
            return (k.modInverse(q) * (hash + x * r) % q);
        }
    }
}
