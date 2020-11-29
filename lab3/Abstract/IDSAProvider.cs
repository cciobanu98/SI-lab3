using DJD.Security;
using lab3.Models;
using System;

namespace lab3.Abstract
{
    public interface IDSAProvider
    {
        DSAInfo GenerateKey();

        Tuple<BigInteger, BigInteger> SignData(byte[] data);

        bool Verify(byte[] data, BigInteger r, BigInteger s);
    }
}
