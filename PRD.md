# Product Requirements Document for SecureChat

## App Overview
- Name: SecureChat
- Tagline: Безопасный мессенджер с централизованной LDAP аутентификацией
- Category: web_application
- Visual Style: Modern Monochrome (e.g. Linear)

## Workflow

Пользователь авторизуется через GLAuth LDAP сервер, получает доступ к списку контактов, может отправлять и получать сообщения в реальном времени. Сообщения проходят через заглушки шифрования перед отправкой и расшифровываются при получении.

## Application Structure


### Route: /

Главная страница мессенджера с формой авторизации через GLAuth LDAP. После входа отображается интерфейс чата с боковой панелью контактов, центральной областью сообщений и полем ввода. Включает индикаторы онлайн статуса и уведомления о новых сообщениях.


### Route: /settings

Страница настроек пользователя с конфигурацией LDAP подключения, управлением ключами шифрования (заглушки), настройками уведомлений и профиля пользователя.


## Potentially Relevant Utility Functions

### setRealtimeStore

Potential usage: Для синхронизации сообщений в реальном времени между пользователями

Look at the documentation for this utility function and determine whether or not it is relevant to the app's requirements.


----------------------------------

### useRealtimeStore

Potential usage: Для получения обновлений сообщений на клиентской стороне

Look at the documentation for this utility function and determine whether or not it is relevant to the app's requirements.


----------------------------------

### getAuth

Potential usage: Для проверки авторизации пользователя

Look at the documentation for this utility function and determine whether or not it is relevant to the app's requirements.

## External APIs
- GLAuth LDAP Server
  - Usage: Аутентификация пользователей через LDAP протокол. Использование ldapjs библиотеки для подключения к GLAuth серверу, проверки учетных данных и получения информации о пользователях и группах.

## Resources
- GLAuth Documentation (reference_site): https://glauth.github.io/docs/
- GLAuth Quick Start (reference_site): https://glauth.github.io/docs/quickstart.html
- GLAuth GitHub Repository (reference_site): https://github.com/glauth/glauth