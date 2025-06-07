# Messenger

Небольшой прототип мессенджера с LDAP‑аутентификацией и заглушками шифрования.

## Установка зависимостей
```bash
npm install
```

## Запуск тестов
```bash
npm test
```

## Учёт изменений
Все важные шаги разработки описываются в файле `DEVLOG.md`.

## Настройка nginx
1. Установите nginx на сервере.
2. Создайте конфигурационный файл `/etc/nginx/sites-available/messenger.conf` со следующим содержимым:

```nginx
server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

3. Активируйте конфигурацию и перезагрузите nginx:
```bash
sudo ln -s /etc/nginx/sites-available/messenger.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## Основные зависимости
Перечень пакетов находится в `package.json`.
