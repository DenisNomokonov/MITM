using System.Numerics;
using System.Security.Cryptography;

namespace CryptoLib
{
    //  Здесь описан алгоритм генерации большого простого числа так, как это было в лабораторных.
    //  Однако мы не можем заставить клиентов всегда генерировать простое число, потому что они будут отличаться
    //  у каждого клиента. Клиенты должны заранее договориться о простом числе и оно должно быть одинаковым.
    //  Поэтому этот код не используется, но может быть использован для разовой генерации числа.
    public static class PrimeGenerator
    {
        public static BigInteger GeneratePrime(int bitLength = 512)
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                while (true)
                {
                    byte[] bytes = new byte[bitLength / 8];
                    rng.GetBytes(bytes);
                    bytes[bytes.Length - 1] |= 0x01; // Делаем число нечётным (чтобы было больше шансов на простоту)

                    BigInteger candidate = new BigInteger(bytes);
                    if (candidate < 0) 
                        candidate = -candidate; // Делаем положительным

                    if (IsPrime(candidate))
                        return candidate;
                }
            }
        }

        private static bool IsPrime(BigInteger number, int rounds = 10)
        {
            if (number < 2) return false;
            if (number % 2 == 0) return number == 2;

            // Тест Миллера-Рабина
            BigInteger d = number - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            Random rnd = new Random();
            for (int i = 0; i < rounds; i++)
            {
                BigInteger a = RandomBigInteger(2, number - 2, rnd);
                BigInteger x = BigInteger.ModPow(a, d, number);

                if (x == 1 || x == number - 1) continue;

                for (int j = 0; j < s - 1; j++)
                {
                    x = BigInteger.ModPow(x, 2, number);
                    if (x == number - 1) break;
                }

                if (x != number - 1) return false;
            }
            return true;
        }

        private static BigInteger RandomBigInteger(BigInteger min, BigInteger max, Random rnd)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger result;
            do
            {
                rnd.NextBytes(bytes);
                result = new BigInteger(bytes);
            } while (result < min || result >= max);

            return result;
        }
    }
}
