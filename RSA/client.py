from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import socket
import threading
from queue import Queue
import base64


def generate_keys():
    # Генерация пары ключей RSA
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def aes_encrypt(message, key):
    # Шифрование сообщения с использованием AES
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_message = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return iv, encrypted_message


def aes_decrypt(encrypted_message, key, iv):
    # Расшифровка сообщения с использованием AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted_message.decode('utf-8')


def rsa_encrypt_key(public_key, aes_key):
    # Шифрование ключа AES с использованием RSA
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(aes_key)


def rsa_decrypt_key(private_key, encrypted_aes_key):
    # Расшифровка ключа AES с использованием RSA
    private_key_obj = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key_obj)
    return cipher_rsa.decrypt(encrypted_aes_key)


def receive_messages(client_socket, private_key, public_key_queue):
    while True:
        try:
            data = client_socket.recv(8192)
            if not data:
                print("Соединение с сервером потеряно.")
                break

            if data.startswith(b"PUBKEY:"):
                public_key = data[len(b"PUBKEY:"):]
                public_key_queue.put(public_key)
            elif data.startswith(b"MSG:"):
                try:
                    # Разбор полученных данных
                    parts = data.decode('utf-8', errors='ignore').split(":", 3)
                    if len(parts) < 4:
                        print("[Ошибка] Неверный формат сообщения.")
                        continue

                    _, sender_name, recipient_name, encrypted_data = parts
                    # Проверяем, что сообщение предназначено нам
                    if recipient_name != name:
                        continue

                    # Декодируем зашифрованные данные из base64
                    encrypted_aes_key_b64, iv_b64, encrypted_message_b64 = encrypted_data.split('||')
                    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
                    iv = base64.b64decode(iv_b64)
                    encrypted_message = base64.b64decode(encrypted_message_b64)

                    # Расшифровываем ключ AES и сообщение
                    aes_key = rsa_decrypt_key(private_key, encrypted_aes_key)
                    decrypted_message = aes_decrypt(encrypted_message, aes_key, iv)
                    print(f"\n[Новое сообщение от {sender_name}]: {decrypted_message}")
                except Exception as e:
                    print(f"[Ошибка при расшифровке сообщения]: {e}")
            else:
                print(f"[Неизвестный формат данных]: {data}")
        except Exception as e:
            print(f"[Ошибка в receive_messages]: {e}")
            break


def request_public_key(client_socket, name, public_key_queue):
    client_socket.send(f"GET_KEY:{name}".encode('utf-8'))
    try:
        public_key = public_key_queue.get(timeout=5)
        return public_key
    except Exception as e:
        print(f"[Ошибка] Не удалось получить публичный ключ: {e}")
        return None


def main():
    global name  # Добавляем глобальную переменную для доступа в других функциях
    host = '127.0.0.1'
    port = 8080

    private_key, public_key = generate_keys()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
        print("Подключено к серверу.")
    except Exception as e:
        print(f"Не удалось подключиться к серверу: {e}")
        return

    name = input("Введите имя клиента: ")
    print(f"Имя клиента: {name}")
    client_socket.send(f"{name}:{public_key.decode('utf-8')}".encode('utf-8'))

    public_key_queue = Queue()
    threading.Thread(target=receive_messages, args=(client_socket, private_key, public_key_queue), daemon=True).start()

    while True:
        message = input("Введите сообщение: ")
        recipient_name = input("Введите имя получателя: ")

        recipient_public_key = request_public_key(client_socket, recipient_name, public_key_queue)
        if not recipient_public_key:
            continue

        aes_key = get_random_bytes(16)
        iv, encrypted_message = aes_encrypt(message, aes_key)
        encrypted_aes_key = rsa_encrypt_key(recipient_public_key, aes_key)

        # Кодируем бинарные данные в base64 для безопасной передачи
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')

        encrypted_data = f"{encrypted_aes_key_b64}||{iv_b64}||{encrypted_message_b64}"

        # Формируем данные в формате: MSG:<sender_name>:<recipient_name>:<encrypted_data>
        data_to_send = f"MSG:{name}:{recipient_name}:{encrypted_data}".encode('utf-8')

        client_socket.send(data_to_send)
        print(f"[Сообщение отправлено]")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Произошла ошибка: {e}")