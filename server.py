import socket
import threading

HOST = '127.0.0.1'
PORT = 8080

clients = {}  # Словарь для хранения подключённых клиентов: {name: connection}
key_sent = False  # Флаг, указывает, был ли ключ уже отправлен
stored_key = None  # Хранит зашифрованный ключ для последующей пересылки


def handle_client(name, conn):
    global key_sent, stored_key

    # Определяем роль клиента (отправитель ключа или получатель ключа)
    if not key_sent:
        conn.send(b"KEY_SENDER")
    else:
        conn.send(b"WAIT_FOR_KEY")
        # Если ключ уже был отправлен, пересылаем его новому клиенту
        if key_sent and stored_key:
            print(f"[Сервер] Отправляем сохранённый ключ -> {name}")
            conn.send(stored_key)

    while True:
        try:
            # Получение данных от клиента
            data = conn.recv(1024)
            if not data:
                break

            print(f"[{name}] Получены данные: {data}")

            # Если это ключ (первые 16 байт - IV, остальное - зашифрованный ключ)
            if not key_sent and len(data) > 16:  # Если это ключ
                key_sent = True
                stored_key = data  # Сохраняем ключ для пересылки
                print(f"[Сервер] Ключ получен от {name}: IV={stored_key[:16]}, Encrypted Key={stored_key[16:]}")

                # Пересылаем ключ всем остальным клиентам
                for client_name, client_conn in clients.items():
                    if client_name != name:  # Исключаем отправителя ключа
                        print(
                            f"[Сервер] Отправляем ключ -> {client_name}: IV={stored_key[:16]}, Encrypted Key={stored_key[16:]}")
                        try:
                            client_conn.send(stored_key)  # Пересылаем ключ
                        except Exception as e:
                            print(f"[Сервер] Ошибка при отправке ключа -> {client_name}: {e}")
                continue

            # Пересылка сообщений всем остальным клиентам
            for client_name, client_conn in clients.items():
                if client_name != name:
                    print(f"[Сервер] Отправляем сообщение -> {client_name}: {data}")
                    try:
                        client_conn.send(data)
                    except Exception as e:
                        print(f"[Сервер] Ошибка при отправке сообщения -> {client_name}: {e}")

        except Exception as e:
            print(f"[Сервер] Ошибка обработки клиента {name}: {e}")
            break

    # Закрытие соединения
    conn.close()
    del clients[name]
    print(f"[{name}] Отключился.")

def main():
    """
    Основной серверный код.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[Сервер] Запущен на {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        name = conn.recv(1024).decode('utf-8')  # Имя клиента
        clients[name] = conn
        print(f"[{name}] Подключился: {addr}")
        threading.Thread(target=handle_client, args=(name, conn)).start()


if __name__ == "__main__":
    main()