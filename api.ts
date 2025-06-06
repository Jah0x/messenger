import { db } from "~/server/db";
import { getAuth, setRealtimeStore } from "~/server/actions";

// LDAP Authentication (заглушка - в реальности нужно использовать ldapjs)
export async function authenticateWithLdap(input: {
  username: string;
  password: string;
}) {
  // ЗАГЛУШКА: В реальности здесь должно быть подключение к GLAuth LDAP серверу
  // const ldap = require('ldapjs');
  // const client = ldap.createClient({ url: 'ldap://localhost:3893' });

  // Простая заглушка для демонстрации
  if (input.username === "admin" && input.password === "password") {
    const ldapDn = `cn=${input.username},ou=users,dc=glauth,dc=com`;

    // Создаем или обновляем пользователя
    const user = await db.user.upsert({
      where: { ldapDn },
      update: {
        isOnline: true,
        lastSeen: new Date(),
      },
      create: {
        ldapDn,
        username: input.username,
        displayName: input.username,
        email: `${input.username}@example.com`,
        isOnline: true,
        // publicKey будет установлен отдельно после генерации на клиенте
      },
    });

    return { success: true, user };
  }

  return { success: false, error: "Invalid credentials" };
}

// Криптографические утилиты для сервера

// Хеширование для вывода ключей (HKDF-like) - зарезервировано для будущего использования
// function deriveKey(sharedSecret: string, salt: string, info: string): Buffer {
//   const hash = createHash("sha256");
//   hash.update(sharedSecret);
//   hash.update(salt);
//   hash.update(info);
//   return hash.digest();
// }

// Генерация случайного salt - зарезервировано для будущего использования
// function generateSalt(): string {
//   return randomBytes(32).toString("base64");
// }

// Проверка формата публичного ключа P-256
function isValidP256PublicKey(key: string): boolean {
  try {
    const buffer = Buffer.from(key, "base64");
    return buffer.length === 65; // P-256 публичные ключи в несжатом формате 65 байт
  } catch {
    return false;
  }
}

// Получить текущего пользователя
export async function getCurrentUser() {
  const { userId } = await getAuth({ required: true });

  // Создаем пользователя если его нет в базе (для Adaptive платформы)
  const user = await db.user.upsert({
    where: { id: userId },
    update: {},
    create: {
      id: userId,
      isOnline: true,
      // publicKey будет установлен после генерации на клиенте
    },
  });

  return user;
}

// Получить список контактов пользователя
export async function getContacts() {
  const { userId } = await getAuth({ required: true });

  const contacts = await db.contact.findMany({
    where: { userId },
    include: {
      contact: {
        select: {
          id: true,
          username: true,
          displayName: true,
          isOnline: true,
          lastSeen: true,
          bio: true,
        },
      },
    },
    orderBy: [
      { contact: { isOnline: "desc" } },
      { contact: { lastSeen: "desc" } },
    ],
  });

  return contacts.map((c) => ({
    ...c.contact,
    nickname: c.nickname,
    addedAt: c.addedAt,
  }));
}

// Поиск пользователей по username
export async function searchUsers(input: { query: string }) {
  const { userId } = await getAuth({ required: true });

  if (!input.query.trim()) {
    return [];
  }

  const users = await db.user.findMany({
    where: {
      AND: [
        { id: { not: userId } },
        {
          OR: [
            { username: { contains: input.query } },
            { displayName: { contains: input.query } },
          ],
        },
      ],
    },
    select: {
      id: true,
      username: true,
      displayName: true,
      bio: true,
      isOnline: true,
      lastSeen: true,
    },
    take: 20,
  });

  // Проверяем, какие пользователи уже добавлены в контакты
  const existingContacts = await db.contact.findMany({
    where: {
      userId,
      contactId: { in: users.map((u) => u.id) },
    },
    select: { contactId: true },
  });

  const existingContactIds = new Set(existingContacts.map((c) => c.contactId));

  return users.map((user) => ({
    ...user,
    isContact: existingContactIds.has(user.id),
  }));
}

// Добавить пользователя в контакты
export async function addContact(input: {
  contactId: string;
  nickname?: string;
}) {
  const { userId } = await getAuth({ required: true });

  // Проверяем, что пользователь существует
  const contactUser = await db.user.findUnique({
    where: { id: input.contactId },
    select: { id: true, username: true, displayName: true },
  });

  if (!contactUser) {
    throw new Error("Пользователь не найден");
  }

  if (contactUser.id === userId) {
    throw new Error("Нельзя добавить себя в контакты");
  }

  // Проверяем, что контакт еще не добавлен
  const existingContact = await db.contact.findUnique({
    where: {
      userId_contactId: {
        userId,
        contactId: input.contactId,
      },
    },
  });

  if (existingContact) {
    throw new Error("Пользователь уже добавлен в контакты");
  }

  const contact = await db.contact.create({
    data: {
      userId,
      contactId: input.contactId,
      nickname: input.nickname,
    },
    include: {
      contact: {
        select: {
          id: true,
          username: true,
          displayName: true,
          bio: true,
          isOnline: true,
          lastSeen: true,
        },
      },
    },
  });

  return {
    ...contact.contact,
    nickname: contact.nickname,
    addedAt: contact.addedAt,
  };
}

// Удалить контакт
export async function removeContact(input: { contactId: string }) {
  const { userId } = await getAuth({ required: true });

  const deletedContact = await db.contact.deleteMany({
    where: {
      userId,
      contactId: input.contactId,
    },
  });

  if (deletedContact.count === 0) {
    throw new Error("Контакт не найден");
  }

  return { success: true };
}

// Получить пользователя по username для ссылок-приглашений
export async function getUserByUsername(input: { username: string }) {
  if (!input.username.trim()) {
    throw new Error("Username не может быть пустым");
  }

  const user = await db.user.findUnique({
    where: { username: input.username },
    select: {
      id: true,
      username: true,
      displayName: true,
      bio: true,
      isOnline: true,
      lastSeen: true,
    },
  });

  if (!user) {
    throw new Error("Пользователь не найден");
  }

  return user;
}

// Отправить зашифрованное сообщение
export async function sendMessage(input: {
  receiverId: string;
  encryptedContent: string;
  encryptedKey: string;
  messageType?: string;
}) {
  const { userId } = await getAuth({ required: true });

  // Проверяем что получатель существует
  const receiver = await db.user.findUnique({
    where: { id: input.receiverId },
    select: { id: true },
  });

  if (!receiver) {
    throw new Error("Recipient not found");
  }

  const message = await db.message.create({
    data: {
      content: input.encryptedContent,
      encryptedKey: input.encryptedKey,
      messageType: input.messageType || "text",
      senderId: userId,
      receiverId: input.receiverId,
      isDelivered: true,
    },
    include: {
      sender: {
        select: {
          id: true,
          username: true,
          displayName: true,
        },
      },
      receiver: {
        select: {
          id: true,
          username: true,
          displayName: true,
        },
      },
    },
  });

  // Отправляем зашифрованное сообщение через realtime store
  await setRealtimeStore({
    channelId: `chat_${input.receiverId}`,
    data: {
      type: "new_message",
      message,
    },
  });

  return message;
}

// Получить зашифрованные сообщения с контактом
export async function getMessages(input: {
  contactId: string;
  limit?: number;
}) {
  const { userId } = await getAuth({ required: true });

  const messages = await db.message.findMany({
    where: {
      OR: [
        { senderId: userId, receiverId: input.contactId },
        { senderId: input.contactId, receiverId: userId },
      ],
    },
    include: {
      sender: {
        select: {
          id: true,
          username: true,
          displayName: true,
        },
      },
    },
    orderBy: { createdAt: "asc" },
    take: input.limit || 50,
  });

  // Возвращаем сообщения как есть - расшифровка происходит на клиенте
  return messages;
}

// Отметить сообщения как прочитанные
export async function markMessagesAsRead(input: { contactId: string }) {
  const { userId } = await getAuth({ required: true });

  await db.message.updateMany({
    where: {
      senderId: input.contactId,
      receiverId: userId,
      isRead: false,
    },
    data: {
      isRead: true,
    },
  });

  return { success: true };
}

// Обновить онлайн статус
export async function updateOnlineStatus(input: { isOnline: boolean }) {
  const { userId } = await getAuth({ required: true });

  // Создаем пользователя если его нет, иначе обновляем
  const user = await db.user.upsert({
    where: { id: userId },
    update: {
      isOnline: input.isOnline,
      lastSeen: new Date(),
    },
    create: {
      id: userId,
      isOnline: input.isOnline,
      lastSeen: new Date(),
      // publicKey будет установлен отдельно
    },
  });

  // Уведомляем всех контактов об изменении статуса
  const contacts = await db.user.findMany({
    where: { id: { not: userId } },
    select: { id: true },
  });

  for (const contact of contacts) {
    await setRealtimeStore({
      channelId: `chat_${contact.id}`,
      data: {
        type: "status_update",
        userId,
        isOnline: input.isOnline,
        lastSeen: user.lastSeen,
      },
    });
  }

  return user;
}

// Получить конфигурацию LDAP
export async function getLdapConfig() {
  const config = await db.ldapConfig.findFirst();
  if (!config) {
    // Создаем конфигурацию по умолчанию
    return await db.ldapConfig.create({
      data: {
        url: "ldap://localhost:3893",
        baseDn: "dc=glauth,dc=com",
        bindDn: "cn=serviceuser,ou=svcaccts,dc=glauth,dc=com",
        bindPass: "mysecret",
      },
    });
  }
  return config;
}

// Обновить конфигурацию LDAP
export async function updateLdapConfig(input: {
  url: string;
  baseDn: string;
  bindDn: string;
  bindPass: string;
}) {
  await getAuth({ required: true });

  const config = await db.ldapConfig.findFirst();
  if (config) {
    return await db.ldapConfig.update({
      where: { id: config.id },
      data: input,
    });
  } else {
    return await db.ldapConfig.create({
      data: input,
    });
  }
}

// Регистрация нового пользователя
export async function registerUser(input: {
  username: string;
  password: string;
  displayName: string;
  email: string;
  bio?: string;
}) {
  // Валидация username
  if (!input.username.match(/^[a-zA-Z0-9_]{3,30}$/)) {
    return {
      success: false,
      error:
        "Username должен содержать только буквы, цифры и подчеркивания (3-30 символов)",
    };
  }

  // Проверка уникальности username и email
  const existingUser = await db.user.findFirst({
    where: {
      OR: [{ username: input.username }, { email: input.email }],
    },
  });

  if (existingUser) {
    if (existingUser.username === input.username) {
      return {
        success: false,
        error: "Пользователь с таким username уже существует",
      };
    } else {
      return {
        success: false,
        error: "Пользователь с таким email уже существует",
      };
    }
  }

  const ldapDn = `cn=${input.username},ou=users,dc=glauth,dc=com`;

  const user = await db.user.create({
    data: {
      ldapDn,
      username: input.username,
      displayName: input.displayName,
      email: input.email,
      bio: input.bio,
      isOnline: false,
      // publicKey будет установлен после генерации на клиенте
    },
  });

  return { success: true, user };
}

// Обновить профиль пользователя
export async function updateUserProfile(input: {
  displayName?: string;
  bio?: string;
}) {
  const { userId } = await getAuth({ required: true });

  const user = await db.user.update({
    where: { id: userId },
    data: {
      displayName: input.displayName,
      bio: input.bio,
    },
    select: {
      id: true,
      username: true,
      displayName: true,
      email: true,
      bio: true,
    },
  });

  return user;
}

// Генерация реального P-256 публичного ключа на сервере (для тестовых пользователей)
async function generateRealP256PublicKey(): Promise<string> {
  const { webcrypto } = await import("node:crypto");

  // Генерируем реальную P-256 ключевую пару
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true, // extractable
    ["deriveKey"],
  );

  // Экспортируем публичный ключ в raw формате
  const publicKeyBuffer = await webcrypto.subtle.exportKey(
    "raw",
    keyPair.publicKey,
  );

  // Конвертируем в base64
  return Buffer.from(publicKeyBuffer).toString("base64");
}

// Seed функция для создания тестовых пользователей с реальными P-256 ключами
export async function _seedTestUsers() {
  const testUsers = [
    {
      username: "alice",
      displayName: "Alice Smith",
      email: "alice@example.com",
      ldapDn: "cn=alice,ou=users,dc=glauth,dc=com",
    },
    {
      username: "bob",
      displayName: "Bob Johnson",
      email: "bob@example.com",
      ldapDn: "cn=bob,ou=users,dc=glauth,dc=com",
    },
    {
      username: "charlie",
      displayName: "Charlie Brown",
      email: "charlie@example.com",
      ldapDn: "cn=charlie,ou=users,dc=glauth,dc=com",
    },
  ];

  for (const userData of testUsers) {
    // Генерируем реальный валидный P-256 публичный ключ для каждого тестового пользователя
    const publicKey = await generateRealP256PublicKey();

    await db.user.upsert({
      where: { ldapDn: userData.ldapDn },
      update: {
        displayName: userData.displayName,
        email: userData.email,
        publicKey: publicKey, // Обновляем с реальным валидным ключом
        isOnline: Math.random() > 0.5, // Случайный онлайн статус
      },
      create: {
        ...userData,
        publicKey: publicKey, // Создаем с реальным валидным ключом
        isOnline: Math.random() > 0.5,
      },
    });
  }

  return { message: "Тестовые пользователи созданы с реальными P-256 ключами" };
}

// Установить публичный ключ пользователя (вызывается после генерации на клиенте)
export async function setUserPublicKey(input: { publicKey: string }) {
  const { userId } = await getAuth({ required: true });

  if (!isValidP256PublicKey(input.publicKey)) {
    throw new Error("Invalid P-256 public key format");
  }

  const user = await db.user.update({
    where: { id: userId },
    data: { publicKey: input.publicKey },
  });

  return { success: true, user };
}

// Получить публичный ключ пользователя
export async function getUserPublicKey(input: { userId: string }) {
  const user = await db.user.findUnique({
    where: { id: input.userId },
    select: { publicKey: true },
  });

  if (!user?.publicKey) {
    throw new Error("User public key not found");
  }

  return { publicKey: user.publicKey };
}
