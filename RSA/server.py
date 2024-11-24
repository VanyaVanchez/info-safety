import socket
import threading

HOST = '127.0.0.1'
PORT = 8080

clients = {}      # {name: connection}
public_keys = {}  # {name: public_key}


def handle_client(name, conn):
    while True:
        try:
            data = conn.recv(8192)
            if not data:
                break

            if data.startswith(b"GET_KEY:"):
                requested_name = data.decode('utf-8').split(":", 1)[1]
                if requested_name in public_keys:
                    conn.send(b"PUBKEY:" + public_keys[requested_name])
                    print(f"[Сервер] Отправлен публичный ключ для {requested_name}.")
                else:
                    conn.send(b"ERROR: Public key not found.")
            elif data.startswith(b"MSG:"):
                try:
                    # Разбор полученных данных
                    parts = data.decode('utf-8', errors='ignore').split(":", 3)
                    if len(parts) < 4:
                        print("[Сервер] Неверный формат сообщения.")
                        continue

                    _, sender_name, recipient_name, encrypted_data = parts
                    if recipient_name in clients:
                        # Пересылаем сообщение получателю
                        clients[recipient_name].send(data)
                        print(f"[Сервер] Сообщение от {sender_name} переслано {recipient_name}.")
                    else:
                        print(f"[Сервер] Клиент {recipient_name} не подключен.")
                except Exception as e:
                    print(f"[Сервер] Ошибка при обработке сообщения: {e}")
            else:
                print(f"[Сервер] Неизвестный формат данных от {name}.")
        except Exception as e:
            print(f"[Сервер] Ошибка обработки клиента {name}: {e}")
            break

    conn.close()
    del clients[name]
    del public_keys[name]
    print(f"[{name}] Отключился.")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[Сервер] Запущен на {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        client_info = conn.recv(8192).decode('utf-8').split(":", 1)
        name = client_info[0]
        public_key = client_info[1].encode('utf-8')

        clients[name] = conn
        public_keys[name] = public_key
        print(f"[{name}] Подключился: {addr}")
        print(f"[{name}] Публичный ключ: {public_key}")

        threading.Thread(target=handle_client, args=(name, conn), daemon=True).start()


if __name__ == "__main__":
    main()