using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using CryptoLib;

class Client
{
    private static TcpClient client;
    private static NetworkStream stream;
    private static Thread receiveThread;
    private static DiffieHellman dh;
    private static byte[] sharedKey;

    static void Main()
    {
        ConnectToServer();
        Console.WriteLine("Введите сообщения для отправки. Для выхода напишите 'exit'.");

        while (true)
        {
            string message = Console.ReadLine();
            if (message?.ToLower() == "exit")
                break;

            if (string.IsNullOrWhiteSpace(message)) continue;

            if (sharedKey == null)
            {
                Console.WriteLine("[!] Ключ шифрования ещё не установлен.");
                continue;
            }

            byte[] encryptedMessage = AesEncryptor.Encrypt(message, sharedKey);
            string base64Message = Convert.ToBase64String(encryptedMessage);

            byte[] data = Encoding.UTF8.GetBytes(base64Message);
            stream.Write(data, 0, data.Length);
            Console.WriteLine($"[Вы]: {message}");
            Console.WriteLine($"[Вы]: {base64Message}");
        }

        Cleanup();
    }

    static void ConnectToServer()
    {
        try
        {
            dh = new DiffieHellman();
            client = new TcpClient("192.168.31.165", 5000);
            stream = client.GetStream();

            byte[] keyData = dh.PublicKey.ToByteArray(isUnsigned: true, isBigEndian: true);
            string base64Key = Convert.ToBase64String(dh.PublicKey.ToByteArray());
            Console.WriteLine(base64Key);

            stream.Write(keyData, 0, keyData.Length);
            stream.Flush();

            receiveThread = new Thread(ReceiveMessages);
            receiveThread.IsBackground = true;
            receiveThread.Start();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка подключения: {ex.Message}");
        }
    }

    static void ReceiveMessages()
    {
        byte[] buffer = new byte[4096];

        while (true)
        {
            try
            {
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead == 0) break;

                string message = Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();

                if (IsBase64(message))
                {
                    if (sharedKey == null)
                    {
                        Console.WriteLine("[!] Получено сообщение до установки ключа.");
                        continue;
                    }

                    string decrypted = AesEncryptor.Decrypt(Convert.FromBase64String(message), sharedKey);
                    Console.WriteLine($"[Сервер]: {decrypted}");
                }
                else
                {
                    byte[] keyBytes = new byte[bytesRead];
                    Array.Copy(buffer, 0, keyBytes, 0, bytesRead);

                    BigInteger otherPublicKey = new BigInteger(keyBytes, isUnsigned: true, isBigEndian: true);
                    BigInteger sharedSecret = dh.ComputeSharedKey(otherPublicKey);
                    sharedKey = SHA256.Create().ComputeHash(sharedSecret.ToByteArray(isUnsigned: true, isBigEndian: true));

                    Console.WriteLine("[Клиент] Установлен общий ключ шифрования.");
                    Console.WriteLine($"[Клиент] sharedKey (hex): {BitConverter.ToString(sharedKey)}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при получении сообщения: {ex.Message}");
                break;
            }
        }
    }

    static bool IsBase64(string str)
    {
        if (string.IsNullOrWhiteSpace(str)) return false;

        if (str.Length % 4 != 0) return false;

        try
        {
            Convert.FromBase64String(str);
            return true;
        }
        catch
        {
            return false;
        }
    }


    static void Cleanup()
    {
        stream?.Close();
        client?.Close();
        receiveThread?.Join();
        Console.WriteLine("Клиент завершил работу.");
    }
}