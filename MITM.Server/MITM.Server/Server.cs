using System;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MITM.Server
{
    class Server
    {
        private static TcpListener server;
        private static List<TcpClient> clients = new List<TcpClient>();
        private static Dictionary<TcpClient, BigInteger> publicKeys = new Dictionary<TcpClient, BigInteger>();
        private static readonly object locker = new object();

        static void Main()
        {
            server = new TcpListener(IPAddress.Any, 5000);
            server.Start();
            Console.WriteLine("[Сервер] Ожидание подключений...");

            while (true)
            {
                TcpClient client = server.AcceptTcpClient();
                lock (locker)
                {
                    clients.Add(client);
                }

                Console.WriteLine("[Сервер] Подключен новый клиент.");

                Thread clientThread = new Thread(() => HandleClient(client));
                clientThread.Start();
            }
        }

        static void HandleClient(TcpClient client)
        {
            NetworkStream stream = client.GetStream();
            byte[] buffer = new byte[4096];

            try
            {
                int keyBytesRead = stream.Read(buffer, 0, buffer.Length);
                byte[] keyBytes = new byte[keyBytesRead];
                Array.Copy(buffer, 0, keyBytes, 0, keyBytesRead);

                BigInteger publicKey = new BigInteger(keyBytes, isUnsigned: true, isBigEndian: true);
                lock (locker)
                {
                    publicKeys[client] = publicKey;
                }

                Console.WriteLine($"[Сервер] Получен публичный ключ ({keyBytes.Length} байт)");

                if (publicKeys.Count == 2)
                {
                    List<TcpClient> clientsList = publicKeys.Keys.ToList();
                    TcpClient client1 = clientsList[0];
                    TcpClient client2 = clientsList[1];

                    BigInteger key1 = publicKeys[client1];
                    BigInteger key2 = publicKeys[client2];

                    byte[] keyForClient1 = key2.ToByteArray(isUnsigned: true, isBigEndian: true);
                    byte[] keyForClient2 = key1.ToByteArray(isUnsigned: true, isBigEndian: true);

                    client1.GetStream().Write(keyForClient1, 0, keyForClient1.Length);
                    client2.GetStream().Write(keyForClient2, 0, keyForClient2.Length);

                    Console.WriteLine("[Сервер] Обмен публичными ключами завершён.");
                }

                while (true)
                {
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;

                    string base64Message = Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();

                    if (!IsBase64(base64Message))
                    {
                        Console.WriteLine("[Сервер] Получено сообщение в некорректном формате.");
                        continue;
                    }

                    Console.WriteLine($"[Сервер] Пересылаем сообщение: {base64Message}");
                    BroadcastMessage(base64Message, sender: client);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Сервер] Ошибка: {ex.Message}");
            }
            finally
            {
                lock (locker)
                {
                    clients.Remove(client); publicKeys.Remove(client);
                }

                client.Close();
                Console.WriteLine("[Сервер] Клиент отключился.");
            }
        }

        static void BroadcastMessage(string message, TcpClient sender)
        {
            byte[] data = Encoding.UTF8.GetBytes(message);

            lock (locker)
            {
                foreach (TcpClient client in clients)
                {
                    if (client != sender)
                    {
                        try
                        {
                            NetworkStream stream = client.GetStream();
                            stream.Write(data, 0, data.Length);
                        }
                        catch
                        {
                            Console.WriteLine("[Сервер] Ошибка при пересылке.");
                        }
                    }
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
            catch { return false; }
        }
    }
}