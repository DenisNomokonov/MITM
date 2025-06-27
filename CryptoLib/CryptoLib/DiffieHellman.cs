using System.Numerics;

namespace CryptoLib
{
    public class DiffieHellman
    {
        private static readonly BigInteger g = 2; // Основа (обычно маленькое число)
        //private static readonly BigInteger p = PrimeGenerator.GeneratePrime(512); // Простое число
        private static readonly BigInteger p = BigInteger.Parse("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171");

        private BigInteger _privateKey;
        private BigInteger _publicKey;

        public BigInteger PrivateKey => _privateKey;
        public BigInteger PublicKey => _publicKey;

        public DiffieHellman()
        {
            Random random = new Random();

            byte[] bytes = new byte[64];
            do
            {
                random.NextBytes(bytes);
                bytes[bytes.Length - 1] &= 0x7F;
                _privateKey = new BigInteger(bytes);
            } while (_privateKey == 0);

            _publicKey = BigInteger.ModPow(g, _privateKey, p);
        }

        public BigInteger ComputeSharedKey(BigInteger otherPublicKey)
        {
            return BigInteger.ModPow(otherPublicKey, PrivateKey, p);
        }
    }
}