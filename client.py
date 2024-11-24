import socket
from threading import Thread
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

channel_key = b"this_is_channel_"  # Заранее известный симметричный ключ (16 байт)
key = None  # Глобальный ключ AES для передачи сообщений


def aes_encrypt(message, key):
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        if isinstance(message, str):  # Если сообщение строка, конвертируем в байты
            message = message.encode('utf-8')
        padded_message = pad(message, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        return iv, ciphertext


def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_data
    except (ValueError, KeyError):
        raise Exception("Ошибка при расшифровке данных. Возможно, использован неверный ключ или IV.")


def receive_messages(client_socket):
    global key
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break

            print(f"[Получено] Данные: {data}")

            if not key:
                # Если ключ AES ещё не установлен, пробуем расшифровать данные как ключ
                iv = data[:16]
                encrypted_key = data[16:]
                print(f"[Получение ключа] IV: {iv}, Encrypted Key: {encrypted_key}")
                try:
                    key = aes_decrypt(encrypted_key, channel_key, iv)  # Расшифровываем ключ
                    print("[Ключ] Ключ AES успешно расшифрован.")
                except Exception as e:
                    print(f"[Ошибка] Не удалось расшифровать ключ: {e}")
                continue

            # Если ключ уже установлен, это сообщение
            iv = data[:16]
            ciphertext = data[16:]
            print(f"[Получение сообщения] IV: {iv}, Ciphertext: {ciphertext}")
            decrypted_message = aes_decrypt(ciphertext, key, iv)
            print(f"[Сообщение] Получено сообщение: {decrypted_message}")

        except Exception as e:
            print(f"[Ошибка] Ошибка при обработке сообщения: {e}")

def main():
    global key
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))

    name = input("Введите имя клиента: ")
    client_socket.send(name.encode('utf-8'))
    print(f"[{name}] Подключение установлено.")

    instruction = client_socket.recv(1024).decode('utf-8')
    print(f"[{name}] Инструкция от сервера: {instruction}")

    Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

    if instruction == "KEY_SENDER":
        key = get_random_bytes(16)
        iv, encrypted_key = aes_encrypt(key, channel_key)
        print(f"[{name}] Отправка ключа: IV={iv}, Encrypted Key={encrypted_key}")
        client_socket.send(iv + encrypted_key)
        print("[Ключ] Ключ отправлен другим клиентам.")

    while True:
        message = input("Введите сообщение: ")
        if not key:
            print("[Ошибка] Ключ ещё не получен. Невозможно отправить сообщение.")
            continue
        if message.lower() == "exit":
            print(f"[{name}] Завершение работы.")
            break
        iv, ciphertext = aes_encrypt(message, key)
        print(f"[Сообщение] Отправка: IV={iv}, Ciphertext={ciphertext}")
        client_socket.send(iv + ciphertext)

    client_socket.close()


if __name__ == "__main__":
    main()