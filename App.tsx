import React, { useState, useEffect, useRef } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  useNavigate,
  Link,
} from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Send,
  Settings,
  Shield,
  MessageCircle,
  Circle,
  Clock,
  Lock,
  Server,
  Menu,
  X,
  UserPlus,
  Key,
  Search,
  Plus,
  Trash2,
  Copy,
  Check,
} from "lucide-react";
import { apiClient } from "~/client/api";
import { useAuth, useRealtimeStore, useToast } from "~/client/utils";
import {
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Input,
  Label,
  Badge,
  Avatar,
  AvatarFallback,
  ScrollArea,
  Separator,
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  Textarea,
} from "~/components/ui";

// Криптографические утилиты для клиента
class CryptoManager {
  private keyPair: CryptoKeyPair | null = null;
  private sharedSecrets = new Map<string, CryptoKey>();

  // Генерация ключевой пары P-256 (ECDH)
  async generateKeyPair(): Promise<void> {
    this.keyPair = await window.crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      false, // не экспортируемый приватный ключ
      ["deriveKey"],
    );
  }

  // Экспорт публичного ключа в base64
  async exportPublicKey(): Promise<string> {
    if (!this.keyPair) {
      throw new Error("Key pair not generated");
    }

    const exported = await window.crypto.subtle.exportKey(
      "raw",
      this.keyPair.publicKey,
    );

    return btoa(String.fromCharCode(...new Uint8Array(exported)));
  }

  // Импорт публичного ключа из base64
  async importPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
    try {
      const keyData = Uint8Array.from(atob(publicKeyBase64), (c) =>
        c.charCodeAt(0),
      );

      // Проверяем длину ключа
      if (keyData.length !== 65) {
        throw new Error(
          `Invalid key length: expected 65 bytes, got ${keyData.length}`,
        );
      }

      // Проверяем что первый байт 0x04 (несжатый формат)
      if (keyData[0] !== 0x04) {
        throw new Error(
          `Invalid key format: expected uncompressed format (0x04), got 0x${keyData[0]?.toString(16) || "undefined"}`,
        );
      }

      return await window.crypto.subtle.importKey(
        "raw",
        keyData,
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        false,
        [],
      );
    } catch (error) {
      console.error("Key import failed:", error);
      throw new Error(
        `Failed to import public key: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  // Вычисление общего секрета (ECDH)
  async deriveSharedSecret(
    contactId: string,
    theirPublicKey: CryptoKey,
  ): Promise<CryptoKey> {
    if (!this.keyPair) {
      throw new Error("Key pair not generated");
    }

    const sharedSecret = await window.crypto.subtle.deriveKey(
      {
        name: "ECDH",
        public: theirPublicKey,
      },
      this.keyPair.privateKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      false,
      ["encrypt", "decrypt"],
    );

    this.sharedSecrets.set(contactId, sharedSecret);
    return sharedSecret;
  }

  // Шифрование сообщения AES-GCM
  async encryptMessage(
    contactId: string,
    message: string,
  ): Promise<{ encryptedContent: string; encryptedKey: string }> {
    const sharedSecret = this.sharedSecrets.get(contactId);
    if (!sharedSecret) {
      throw new Error("Shared secret not found for contact");
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV для GCM

    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      sharedSecret,
      data,
    );

    // Объединяем IV и зашифрованные данные
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return {
      encryptedContent: btoa(String.fromCharCode(...combined)),
      encryptedKey: btoa(String.fromCharCode(...iv)), // IV как "ключ"
    };
  }

  // Расшифровка сообщения AES-GCM
  async decryptMessage(
    contactId: string,
    encryptedContent: string,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _encryptedKey: string,
  ): Promise<string> {
    const sharedSecret = this.sharedSecrets.get(contactId);
    if (!sharedSecret) {
      throw new Error("Shared secret not found for contact");
    }

    try {
      const combined = Uint8Array.from(atob(encryptedContent), (c) =>
        c.charCodeAt(0),
      );
      const iv = combined.slice(0, 12);
      const data = combined.slice(12);

      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        sharedSecret,
        data,
      );

      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (error) {
      console.error("Decryption failed:", error);
      return "[Не удалось расшифровать сообщение]";
    }
  }

  // Проверка наличия общего секрета
  hasSharedSecret(contactId: string): boolean {
    return this.sharedSecrets.has(contactId);
  }
}

// Глобальный экземпляр менеджера криптографии
const cryptoManager = new CryptoManager();

// Компонент авторизации
function LoginForm() {
  const [credentials, setCredentials] = useState({
    username: "",
    password: "",
  });

  const { toast } = useToast();
  const navigate = useNavigate();

  const loginMutation = useMutation(apiClient.authenticateWithLdap, {
    onSuccess: (data) => {
      if (data.success) {
        toast({
          title: "Успешная авторизация",
          description: "Добро пожаловать в SecureChat!",
        });
        navigate("/");
      } else {
        toast({
          title: "Ошибка авторизации",
          description: data.error || "Неверные учетные данные",
          variant: "destructive",
        });
      }
    },
    onError: () => {
      toast({
        title: "Ошибка подключения",
        description: "Не удалось подключиться к LDAP серверу",
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (credentials.username && credentials.password) {
      loginMutation.mutate(credentials);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        <Card>
          <CardHeader className="text-center">
            <div className="flex items-center justify-center mb-4">
              <Shield className="h-8 w-8 text-primary mr-2" />
              <CardTitle className="text-2xl">SecureChat</CardTitle>
            </div>
            <p className="text-muted-foreground">
              Войдите через LDAP для доступа к защищенному мессенджеру
            </p>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="username">Имя пользователя</Label>
                <Input
                  id="username"
                  type="text"
                  value={credentials.username}
                  onChange={(e) =>
                    setCredentials((prev) => ({
                      ...prev,
                      username: e.target.value,
                    }))
                  }
                  placeholder="Введите имя пользователя"
                  required
                />
              </div>
              <div>
                <Label htmlFor="password">Пароль</Label>
                <Input
                  id="password"
                  type="password"
                  value={credentials.password}
                  onChange={(e) =>
                    setCredentials((prev) => ({
                      ...prev,
                      password: e.target.value,
                    }))
                  }
                  placeholder="Введите пароль"
                  required
                />
              </div>
              <Button
                type="submit"
                className="w-full"
                disabled={loginMutation.isLoading}
              >
                {loginMutation.isLoading ? "Вход..." : "Войти"}
              </Button>
            </form>
            <div className="mt-4 text-center text-sm text-muted-foreground space-y-2">
              <p>Демо: admin / password</p>
              <p>
                Нет аккаунта?{" "}
                <Link to="/register" className="text-primary hover:underline">
                  Зарегистрироваться
                </Link>
              </p>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}

// Компонент контакта
function ContactItem({
  contact,
  isSelected,
  onClick,
  unreadCount,
}: {
  contact: any;
  isSelected: boolean;
  onClick: () => void;
  unreadCount: number;
}) {
  return (
    <motion.div
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      className={`p-3 rounded-lg cursor-pointer transition-colors ${
        isSelected ? "bg-accent" : "hover:bg-accent/50"
      }`}
      onClick={onClick}
    >
      <div className="flex items-center space-x-3">
        <div className="relative">
          <Avatar className="h-10 w-10">
            <AvatarFallback>
              {contact.displayName?.charAt(0) || contact.username.charAt(0)}
            </AvatarFallback>
          </Avatar>
          <div
            className={`absolute -bottom-1 -right-1 w-3 h-3 rounded-full border-2 border-background ${
              contact.isOnline ? "online-indicator" : "offline-indicator"
            }`}
          />
        </div>
        <div className="flex-1 min-w-0">
          <p className="font-medium truncate text-sm">
            {contact.displayName || contact.username || "Пользователь"}
          </p>
          <p className="text-xs text-muted-foreground flex items-center">
            {contact.isOnline ? (
              <>
                <Circle className="h-2 w-2 fill-current text-green-500 mr-1" />
                Онлайн
              </>
            ) : (
              <>
                <Clock className="h-3 w-3 mr-1" />
                {new Date(contact.lastSeen).toLocaleTimeString()}
              </>
            )}
          </p>
        </div>
        {unreadCount > 0 && (
          <Badge variant="destructive" className="text-xs">
            {unreadCount}
          </Badge>
        )}
      </div>
    </motion.div>
  );
}

// Компонент сообщения
function MessageBubble({
  message,
  isOwn,
  decryptedContent,
}: {
  message: any;
  isOwn: boolean;
  decryptedContent?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`flex ${isOwn ? "justify-end" : "justify-start"} mb-4`}
    >
      <div
        className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
          isOwn ? "chat-bubble-sent" : "chat-bubble-received"
        }`}
      >
        <p className="text-sm">{decryptedContent || "[Расшифровка...]"}</p>
        <div className="flex items-center justify-between mt-1">
          <p className="text-xs text-muted-foreground">
            {new Date(message.createdAt).toLocaleTimeString()}
          </p>
          <div className="flex items-center space-x-1">
            <Lock className="h-3 w-3 text-green-500" />
            {isOwn && message.isDelivered && (
              <span className="text-xs text-muted-foreground">✓</span>
            )}
            {isOwn && message.isRead && (
              <span className="text-xs text-muted-foreground">✓</span>
            )}
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// Компонент поиска пользователей
function AddContactDialog({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedUser, setSelectedUser] = useState<any>(null);
  const [nickname, setNickname] = useState("");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Поиск пользователей
  const { data: searchResults = [] } = useQuery(
    ["searchUsers", searchQuery],
    () => apiClient.searchUsers({ query: searchQuery }),
    {
      enabled: searchQuery.trim().length > 0,
      staleTime: 30000,
    },
  );

  // Добавление контакта
  const addContactMutation = useMutation(apiClient.addContact, {
    onSuccess: () => {
      toast({
        title: "Контакт добавлен",
        description: "Пользователь успешно добавлен в контакты",
      });
      queryClient.invalidateQueries(["contacts"]);
      onClose();
      setSearchQuery("");
      setSelectedUser(null);
      setNickname("");
    },
    onError: (error: any) => {
      toast({
        title: "Ошибка",
        description: error.message || "Не удалось добавить контакт",
        variant: "destructive",
      });
    },
  });

  const handleAddContact = () => {
    if (selectedUser) {
      addContactMutation.mutate({
        contactId: selectedUser.id,
        nickname: nickname.trim() || undefined,
      });
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Добавить контакт</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="search">Поиск пользователей</Label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                id="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Введите username или имя"
                className="pl-10"
              />
            </div>
          </div>

          {searchResults.length > 0 && (
            <ScrollArea className="h-48 border rounded-md">
              <div className="p-2 space-y-2">
                {searchResults.map((user) => (
                  <div
                    key={user.id}
                    className={`p-2 rounded-lg cursor-pointer transition-colors ${
                      selectedUser?.id === user.id
                        ? "bg-accent"
                        : "hover:bg-accent/50"
                    }`}
                    onClick={() => setSelectedUser(user)}
                  >
                    <div className="flex items-center space-x-3">
                      <Avatar className="h-8 w-8">
                        <AvatarFallback>
                          {user.displayName?.charAt(0) ||
                            user.username?.charAt(0)}
                        </AvatarFallback>
                      </Avatar>
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm truncate">
                          {user.displayName || user.username}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          @{user.username}
                        </p>
                        {user.bio && (
                          <p className="text-xs text-muted-foreground truncate">
                            {user.bio}
                          </p>
                        )}
                      </div>
                      <div className="flex items-center space-x-2">
                        {user.isContact ? (
                          <Badge variant="secondary" className="text-xs">
                            В контактах
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-xs">
                            Добавить
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}

          {selectedUser && !selectedUser.isContact && (
            <div>
              <Label htmlFor="nickname">Псевдоним (необязательно)</Label>
              <Input
                id="nickname"
                value={nickname}
                onChange={(e) => setNickname(e.target.value)}
                placeholder="Как отображать в контактах"
              />
            </div>
          )}

          <div className="flex justify-end space-x-2">
            <Button variant="outline" onClick={onClose}>
              Отмена
            </Button>
            <Button
              onClick={handleAddContact}
              disabled={
                !selectedUser ||
                selectedUser.isContact ||
                addContactMutation.isLoading
              }
            >
              {addContactMutation.isLoading ? "Добавление..." : "Добавить"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// Компонент профиля пользователя
function UserProfileDialog({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) {
  const { data: currentUser } = useQuery(
    ["currentUser"],
    apiClient.getCurrentUser,
  );
  const [profileData, setProfileData] = useState({
    displayName: "",
    bio: "",
  });
  const [copiedUsername, setCopiedUsername] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  useEffect(() => {
    if (currentUser) {
      setProfileData({
        displayName: currentUser.displayName || "",
        bio: currentUser.bio || "",
      });
    }
  }, [currentUser]);

  const updateProfileMutation = useMutation(apiClient.updateUserProfile, {
    onSuccess: () => {
      toast({
        title: "Профиль обновлен",
        description: "Изменения сохранены",
      });
      queryClient.invalidateQueries(["currentUser"]);
    },
    onError: () => {
      toast({
        title: "Ошибка",
        description: "Не удалось обновить профиль",
        variant: "destructive",
      });
    },
  });

  const handleSave = () => {
    updateProfileMutation.mutate(profileData);
  };

  const copyUsername = async () => {
    if (currentUser?.username) {
      try {
        // @ts-ignore
        const copyModule = (await import("copy-to-clipboard")) as {
          default: (text: string) => boolean;
        };
        if (copyModule.default) {
          copyModule.default(`@${currentUser.username}`);
        }
        setCopiedUsername(true);
        toast({
          title: "Скопировано",
          description: "Username скопирован в буфер обмена",
        });
        setTimeout(() => setCopiedUsername(false), 2000);
      } catch (error) {
        console.error("Failed to copy:", error);
      }
    }
  };

  if (!currentUser) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Профиль пользователя</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="flex items-center space-x-4">
            <Avatar className="h-16 w-16">
              <AvatarFallback className="text-lg">
                {currentUser.displayName?.charAt(0) ||
                  currentUser.username?.charAt(0) ||
                  "U"}
              </AvatarFallback>
            </Avatar>
            <div className="flex-1">
              <h3 className="font-semibold">
                {currentUser.displayName || currentUser.username}
              </h3>
              <div className="flex items-center space-x-2">
                <p className="text-sm text-muted-foreground">
                  @{currentUser.username}
                </p>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={copyUsername}
                  className="h-6 px-2"
                >
                  {copiedUsername ? (
                    <Check className="h-3 w-3" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                </Button>
              </div>
            </div>
          </div>

          <Separator />

          <div>
            <Label htmlFor="displayName">Отображаемое имя</Label>
            <Input
              id="displayName"
              value={profileData.displayName}
              onChange={(e) =>
                setProfileData((prev) => ({
                  ...prev,
                  displayName: e.target.value,
                }))
              }
              placeholder="Ваше полное имя"
            />
          </div>

          <div>
            <Label htmlFor="bio">О себе</Label>
            <Textarea
              id="bio"
              value={profileData.bio}
              onChange={(e) =>
                setProfileData((prev) => ({
                  ...prev,
                  bio: e.target.value,
                }))
              }
              placeholder="Расскажите о себе..."
              rows={3}
            />
          </div>

          <div className="flex justify-end space-x-2">
            <Button variant="outline" onClick={onClose}>
              Отмена
            </Button>
            <Button
              onClick={handleSave}
              disabled={updateProfileMutation.isLoading}
            >
              {updateProfileMutation.isLoading ? "Сохранение..." : "Сохранить"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// Компонент регистрации
function RegisterForm() {
  const [formData, setFormData] = useState({
    username: "",
    password: "",
    displayName: "",
    email: "",
    bio: "",
  });

  const { toast } = useToast();
  const navigate = useNavigate();

  const registerMutation = useMutation(apiClient.registerUser, {
    onSuccess: (data) => {
      if (data.success) {
        toast({
          title: "Регистрация успешна",
          description: "Теперь вы можете войти в систему",
        });
        navigate("/login");
      } else {
        toast({
          title: "Ошибка регистрации",
          description: data.error || "Не удалось создать аккаунт",
          variant: "destructive",
        });
      }
    },
    onError: () => {
      toast({
        title: "Ошибка",
        description: "Не удалось создать аккаунт",
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (Object.values(formData).every((val) => val.trim())) {
      registerMutation.mutate(formData);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        <Card>
          <CardHeader className="text-center">
            <div className="flex items-center justify-center mb-4">
              <UserPlus className="h-8 w-8 text-primary mr-2" />
              <CardTitle className="text-2xl">Регистрация</CardTitle>
            </div>
            <p className="text-muted-foreground">
              Создайте новый аккаунт для SecureChat
            </p>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="username">Имя пользователя</Label>
                <Input
                  id="username"
                  type="text"
                  value={formData.username}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      username: e.target.value,
                    }))
                  }
                  placeholder="Введите имя пользователя"
                  required
                />
              </div>
              <div>
                <Label htmlFor="displayName">Отображаемое имя</Label>
                <Input
                  id="displayName"
                  type="text"
                  value={formData.displayName}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      displayName: e.target.value,
                    }))
                  }
                  placeholder="Ваше полное имя"
                  required
                />
              </div>
              <div>
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={formData.email}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      email: e.target.value,
                    }))
                  }
                  placeholder="your@email.com"
                  required
                />
              </div>
              <div>
                <Label htmlFor="password">Пароль</Label>
                <Input
                  id="password"
                  type="password"
                  value={formData.password}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      password: e.target.value,
                    }))
                  }
                  placeholder="Введите пароль"
                  required
                />
              </div>
              <div>
                <Label htmlFor="bio">О себе (необязательно)</Label>
                <Textarea
                  id="bio"
                  value={formData.bio}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      bio: e.target.value,
                    }))
                  }
                  placeholder="Расскажите о себе..."
                  rows={3}
                />
              </div>
              <Button
                type="submit"
                className="w-full"
                disabled={registerMutation.isLoading}
              >
                {registerMutation.isLoading ? "Создание..." : "Создать аккаунт"}
              </Button>
            </form>
            <div className="mt-4 text-center text-sm text-muted-foreground">
              <p>
                Уже есть аккаунт?{" "}
                <Link to="/login" className="text-primary hover:underline">
                  Войти
                </Link>
              </p>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}

// Главный компонент чата
function ChatInterface() {
  const [selectedContact, setSelectedContact] = useState<any>(null);
  const [messageText, setMessageText] = useState("");
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [keysGenerated, setKeysGenerated] = useState(false);
  const [decryptedMessages, setDecryptedMessages] = useState<
    Map<string, string>
  >(new Map());
  const [showAddContact, setShowAddContact] = useState(false);
  const [showProfile, setShowProfile] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // Получаем данные пользователя
  const { data: currentUser } = useQuery(
    ["currentUser"],
    apiClient.getCurrentUser,
  );

  // Получаем контакты
  const { data: contacts = [] } = useQuery(
    ["contacts"],
    apiClient.getContacts,
    {
      refetchInterval: 30000, // Обновляем каждые 30 секунд
    },
  );

  // Получаем сообщения с выбранным контактом
  const { data: messages = [] } = useQuery(
    ["messages", selectedContact?.id],
    () => apiClient.getMessages({ contactId: selectedContact.id }),
    { enabled: !!selectedContact },
  );

  // Realtime обновления для текущего пользователя
  const [realtimeData] = useRealtimeStore(
    currentUser ? `chat_${currentUser.id}` : "",
    { type: "init" },
  );

  // Отправка зашифрованного сообщения
  const sendMessageMutation = useMutation(apiClient.sendMessage, {
    onSuccess: () => {
      setMessageText("");
      queryClient.invalidateQueries(["messages", selectedContact?.id]);
      scrollToBottom();
    },
    onError: () => {
      toast({
        title: "Ошибка отправки",
        description: "Не удалось отправить сообщение",
        variant: "destructive",
      });
    },
  });

  // Установка публичного ключа
  const setPublicKeyMutation = useMutation(apiClient.setUserPublicKey);

  // Получение публичного ключа контакта
  const getPublicKeyMutation = useMutation(apiClient.getUserPublicKey);

  // Отметка сообщений как прочитанных
  const markAsReadMutation = useMutation(apiClient.markMessagesAsRead);

  // Обновление онлайн статуса
  const updateStatusMutation = useMutation(apiClient.updateOnlineStatus);

  // Удаление контакта
  const removeContactMutation = useMutation(apiClient.removeContact, {
    onSuccess: () => {
      toast({
        title: "Контакт удален",
        description: "Пользователь удален из контактов",
      });
      queryClient.invalidateQueries(["contacts"]);
      if (selectedContact) {
        setSelectedContact(null);
      }
    },
    onError: () => {
      toast({
        title: "Ошибка",
        description: "Не удалось удалить контакт",
        variant: "destructive",
      });
    },
  });

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    if (selectedContact) {
      markAsReadMutation.mutate({ contactId: selectedContact.id });
    }
  }, [selectedContact]);

  // Обработка realtime обновлений
  useEffect(() => {
    if (realtimeData?.type === "new_message") {
      queryClient.invalidateQueries(["messages"]);
      queryClient.invalidateQueries(["contacts"]);
    } else if (realtimeData?.type === "status_update") {
      queryClient.invalidateQueries(["contacts"]);
    }
  }, [realtimeData, queryClient]);

  // Генерация ключей при загрузке
  useEffect(() => {
    const initializeCrypto = async () => {
      try {
        await cryptoManager.generateKeyPair();
        const publicKey = await cryptoManager.exportPublicKey();

        // Отправляем публичный ключ на сервер
        await setPublicKeyMutation.mutateAsync({ publicKey });
        setKeysGenerated(true);

        toast({
          title: "Ключи сгенерированы",
          description:
            "Криптографические ключи созданы и готовы к использованию",
        });
      } catch (error) {
        console.error("Failed to initialize crypto:", error);
        toast({
          title: "Ошибка криптографии",
          description: "Не удалось сгенерировать ключи шифрования",
          variant: "destructive",
        });
      }
    };

    initializeCrypto();
    updateStatusMutation.mutate({ isOnline: true });

    const handleBeforeUnload = () => {
      updateStatusMutation.mutate({ isOnline: false });
    };

    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => {
      window.removeEventListener("beforeunload", handleBeforeUnload);
      updateStatusMutation.mutate({ isOnline: false });
    };
  }, []);

  // Установка общего секрета с контактом
  const setupSharedSecret = async (contactId: string) => {
    if (cryptoManager.hasSharedSecret(contactId)) {
      return; // Уже настроен
    }

    try {
      const { publicKey } = await getPublicKeyMutation.mutateAsync({
        userId: contactId,
      });

      // Проверяем, что публичный ключ валиден
      if (
        !publicKey ||
        publicKey.includes("STUB_KEY") ||
        publicKey.includes("BEGIN PUBLIC KEY")
      ) {
        throw new Error(
          "Контакт использует устаревший формат ключей. Попросите его перезайти в приложение.",
        );
      }

      const theirPublicKey = await cryptoManager.importPublicKey(publicKey);
      await cryptoManager.deriveSharedSecret(contactId, theirPublicKey);

      toast({
        title: "Защищенное соединение установлено",
        description: "Теперь ваши сообщения полностью зашифрованы",
      });
    } catch (error) {
      console.error("Failed to setup shared secret:", error);
      const errorMessage =
        error instanceof Error
          ? error.message
          : "Не удалось установить защищенное соединение";
      toast({
        title: "Ошибка шифрования",
        description: errorMessage,
        variant: "destructive",
      });
    }
  };

  // Расшифровка сообщений
  const decryptMessages = async (messages: any[], contactId: string) => {
    if (!cryptoManager.hasSharedSecret(contactId)) {
      await setupSharedSecret(contactId);
    }

    const newDecrypted = new Map(decryptedMessages);

    for (const message of messages) {
      if (!newDecrypted.has(message.id)) {
        try {
          const decrypted = await cryptoManager.decryptMessage(
            contactId,
            message.content,
            message.encryptedKey,
          );
          newDecrypted.set(message.id, decrypted);
        } catch (error) {
          console.error("Failed to decrypt message:", error);
          newDecrypted.set(message.id, "[Ошибка расшифровки]");
        }
      }
    }

    setDecryptedMessages(newDecrypted);
  };

  // Обработка выбора контакта
  useEffect(() => {
    if (selectedContact && messages.length > 0) {
      decryptMessages(messages, selectedContact.id);
    }
  }, [selectedContact, messages]);

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!messageText.trim() || !selectedContact || !keysGenerated) {
      return;
    }

    try {
      // Устанавливаем общий секрет если его нет
      if (!cryptoManager.hasSharedSecret(selectedContact.id)) {
        await setupSharedSecret(selectedContact.id);
      }

      // Шифруем сообщение
      const { encryptedContent, encryptedKey } =
        await cryptoManager.encryptMessage(
          selectedContact.id,
          messageText.trim(),
        );

      // Отправляем зашифрованное сообщение
      sendMessageMutation.mutate({
        receiverId: selectedContact.id,
        encryptedContent,
        encryptedKey,
      });
    } catch (error) {
      console.error("Failed to send encrypted message:", error);
      toast({
        title: "Ошибка шифрования",
        description: "Не удалось зашифровать сообщение",
        variant: "destructive",
      });
    }
  };

  return (
    <div className="h-screen bg-background flex flex-col">
      {/* Мобильный header */}
      <div className="md:hidden flex items-center justify-between p-4 border-b bg-card">
        <div className="flex items-center space-x-2">
          <Shield className="h-6 w-6 text-primary" />
          <h1 className="text-lg font-bold">SecureChat</h1>
        </div>
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setIsSidebarOpen(true)}
        >
          <Menu className="h-5 w-5" />
        </Button>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Десктопная боковая панель */}
        <div className="hidden md:flex md:w-80 lg:w-96 border-r bg-card flex-col">
          <div className="p-4 border-b">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Shield className="h-6 w-6 text-primary" />
                <h1 className="text-xl font-bold">SecureChat</h1>
              </div>
              <Dialog>
                <DialogTrigger asChild>
                  <Button variant="ghost" size="icon">
                    <Settings className="h-4 w-4" />
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Настройки</DialogTitle>
                  </DialogHeader>
                  <SettingsContent />
                </DialogContent>
              </Dialog>
            </div>
            {currentUser && (
              <div
                className="mt-3 flex items-center space-x-2 p-2 rounded-lg hover:bg-accent/50 cursor-pointer transition-colors"
                onClick={() => setShowProfile(true)}
              >
                <Avatar className="h-8 w-8">
                  <AvatarFallback>
                    {currentUser.displayName?.charAt(0) ||
                      currentUser.username?.charAt(0) ||
                      "U"}
                  </AvatarFallback>
                </Avatar>
                <div className="min-w-0 flex-1">
                  <p className="font-medium text-sm truncate">
                    {currentUser.displayName ||
                      currentUser.username ||
                      "Пользователь"}
                  </p>
                  <p className="text-xs text-muted-foreground flex items-center">
                    <Circle className="h-2 w-2 fill-current text-green-500 mr-1" />
                    Онлайн
                  </p>
                </div>
              </div>
            )}
          </div>

          <div className="px-4 pb-2">
            <Button
              variant="outline"
              className="w-full"
              onClick={() => setShowAddContact(true)}
            >
              <Plus className="h-4 w-4 mr-2" />
              Добавить контакт
            </Button>
          </div>

          <ScrollArea className="flex-1">
            <div className="p-2">
              {contacts.map((contact) => (
                <div key={contact.id} className="group relative">
                  <ContactItem
                    contact={contact}
                    isSelected={selectedContact?.id === contact.id}
                    onClick={() => setSelectedContact(contact)}
                    unreadCount={0}
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity h-6 w-6 p-0"
                    onClick={(e) => {
                      e.stopPropagation();
                      removeContactMutation.mutate({ contactId: contact.id });
                    }}
                    title="Удалить контакт"
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>

        {/* Мобильная боковая панель (drawer) */}
        <AnimatePresence>
          {isSidebarOpen && (
            <>
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="md:hidden fixed inset-0 bg-black/50 z-40"
                onClick={() => setIsSidebarOpen(false)}
              />
              <motion.div
                initial={{ x: "-100%" }}
                animate={{ x: 0 }}
                exit={{ x: "-100%" }}
                transition={{ type: "spring", damping: 25, stiffness: 200 }}
                className="md:hidden fixed left-0 top-0 bottom-0 w-80 bg-card border-r z-50 flex flex-col"
              >
                <div className="p-4 border-b">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Shield className="h-6 w-6 text-primary" />
                      <h1 className="text-lg font-bold">SecureChat</h1>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setIsSidebarOpen(false)}
                    >
                      <X className="h-5 w-5" />
                    </Button>
                  </div>
                  {currentUser && (
                    <div
                      className="mt-3 flex items-center space-x-2 p-2 rounded-lg hover:bg-accent/50 cursor-pointer transition-colors"
                      onClick={() => {
                        setShowProfile(true);
                        setIsSidebarOpen(false);
                      }}
                    >
                      <Avatar className="h-8 w-8">
                        <AvatarFallback>
                          {currentUser.displayName?.charAt(0) ||
                            currentUser.username?.charAt(0) ||
                            "U"}
                        </AvatarFallback>
                      </Avatar>
                      <div className="min-w-0 flex-1">
                        <p className="font-medium text-sm truncate">
                          {currentUser.displayName ||
                            currentUser.username ||
                            "Пользователь"}
                        </p>
                        <p className="text-xs text-muted-foreground flex items-center">
                          <Circle className="h-2 w-2 fill-current text-green-500 mr-1" />
                          Онлайн
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                <div className="px-4 pb-2">
                  <Button
                    variant="outline"
                    className="w-full"
                    onClick={() => {
                      setShowAddContact(true);
                      setIsSidebarOpen(false);
                    }}
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    Добавить контакт
                  </Button>
                </div>

                <ScrollArea className="flex-1">
                  <div className="p-2">
                    {contacts.map((contact) => (
                      <div key={contact.id} className="group relative">
                        <ContactItem
                          contact={contact}
                          isSelected={selectedContact?.id === contact.id}
                          onClick={() => {
                            setSelectedContact(contact);
                            setIsSidebarOpen(false);
                          }}
                          unreadCount={0}
                        />
                        <Button
                          variant="ghost"
                          size="sm"
                          className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity h-6 w-6 p-0"
                          onClick={(e) => {
                            e.stopPropagation();
                            removeContactMutation.mutate({
                              contactId: contact.id,
                            });
                          }}
                          title="Удалить контакт"
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </motion.div>
            </>
          )}
        </AnimatePresence>

        {/* Область чата */}
        <div className="flex-1 flex flex-col min-h-0">
          <AddContactDialog
            isOpen={showAddContact}
            onClose={() => setShowAddContact(false)}
          />
          <UserProfileDialog
            isOpen={showProfile}
            onClose={() => setShowProfile(false)}
          />
          {selectedContact ? (
            <>
              {/* Заголовок чата */}
              <div className="p-3 md:p-4 border-b bg-card">
                <div className="flex items-center space-x-3">
                  <Avatar className="h-8 w-8 md:h-10 md:w-10">
                    <AvatarFallback>
                      {selectedContact.displayName?.charAt(0) ||
                        selectedContact.username.charAt(0)}
                    </AvatarFallback>
                  </Avatar>
                  <div className="min-w-0 flex-1">
                    <h2 className="font-semibold text-sm md:text-base truncate">
                      {selectedContact.displayName || selectedContact.username}
                    </h2>
                    <p className="text-xs md:text-sm text-muted-foreground flex items-center">
                      {selectedContact.isOnline ? (
                        <>
                          <Circle className="h-2 w-2 fill-current text-green-500 mr-1" />
                          Онлайн
                        </>
                      ) : (
                        <>
                          <Clock className="h-3 w-3 mr-1" />
                          Был в сети{" "}
                          {new Date(
                            selectedContact.lastSeen,
                          ).toLocaleTimeString()}
                        </>
                      )}
                    </p>
                  </div>
                  <div className="ml-auto flex items-center space-x-2">
                    {cryptoManager.hasSharedSecret(selectedContact.id) ? (
                      <Badge variant="default" className="text-xs bg-green-600">
                        <Lock className="h-3 w-3 mr-1" />
                        E2E активен
                      </Badge>
                    ) : (
                      <Badge variant="secondary" className="text-xs">
                        <Key className="h-3 w-3 mr-1" />
                        Настройка...
                      </Badge>
                    )}
                  </div>
                </div>
              </div>

              {/* Сообщения */}
              <ScrollArea className="flex-1 p-2 md:p-4">
                <div className="space-y-2">
                  {messages.map((message) => (
                    <MessageBubble
                      key={message.id}
                      message={message}
                      isOwn={message.senderId === currentUser?.id}
                      decryptedContent={decryptedMessages.get(message.id)}
                    />
                  ))}
                  <div ref={messagesEndRef} />
                </div>
              </ScrollArea>

              {/* Поле ввода */}
              <div className="p-2 md:p-4 border-t bg-card">
                <form onSubmit={handleSendMessage} className="flex space-x-2">
                  <Input
                    value={messageText}
                    onChange={(e) => setMessageText(e.target.value)}
                    placeholder="Сообщение..."
                    className="flex-1 text-sm"
                  />
                  <Button
                    type="submit"
                    size="icon"
                    disabled={
                      !messageText.trim() ||
                      sendMessageMutation.isLoading ||
                      !keysGenerated
                    }
                    title={
                      !keysGenerated
                        ? "Ожидание генерации ключей..."
                        : "Отправить зашифрованное сообщение"
                    }
                  >
                    <Send className="h-4 w-4" />
                  </Button>
                </form>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center p-4">
              <div className="text-center max-w-md mx-auto">
                <MessageCircle className="h-12 w-12 md:h-16 md:w-16 text-muted-foreground mx-auto mb-4" />
                <h3 className="text-lg md:text-xl font-semibold mb-2">
                  Выберите контакт
                </h3>
                <p className="text-muted-foreground text-sm md:text-base">
                  {contacts.length > 0
                    ? "Выберите контакт из списка, чтобы начать защищенную переписку"
                    : "Пока нет доступных контактов. Попробуйте обновить страницу."}
                </p>
                <div className="md:hidden mt-4">
                  <Button
                    variant="outline"
                    onClick={() => setIsSidebarOpen(true)}
                    className="flex items-center space-x-2"
                  >
                    <Menu className="h-4 w-4" />
                    <span>Открыть список контактов</span>
                  </Button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Компонент настроек
function SettingsContent() {
  const { data: ldapConfig } = useQuery(
    ["ldapConfig"],
    apiClient.getLdapConfig,
  );
  const [config, setConfig] = useState({
    url: "",
    baseDn: "",
    bindDn: "",
    bindPass: "",
  });

  const updateConfigMutation = useMutation(apiClient.updateLdapConfig);

  useEffect(() => {
    if (ldapConfig) {
      setConfig(ldapConfig);
    }
  }, [ldapConfig]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateConfigMutation.mutate(config);
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <Server className="h-5 w-5 mr-2" />
          Настройки LDAP
        </h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <Label htmlFor="url">URL сервера</Label>
            <Input
              id="url"
              value={config.url}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, url: e.target.value }))
              }
              placeholder="ldap://localhost:3893"
            />
          </div>
          <div>
            <Label htmlFor="baseDn">Base DN</Label>
            <Input
              id="baseDn"
              value={config.baseDn}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, baseDn: e.target.value }))
              }
              placeholder="dc=glauth,dc=com"
            />
          </div>
          <div>
            <Label htmlFor="bindDn">Bind DN</Label>
            <Input
              id="bindDn"
              value={config.bindDn}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, bindDn: e.target.value }))
              }
              placeholder="cn=serviceuser,ou=svcaccts,dc=glauth,dc=com"
            />
          </div>
          <div>
            <Label htmlFor="bindPass">Пароль</Label>
            <Input
              id="bindPass"
              type="password"
              value={config.bindPass}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, bindPass: e.target.value }))
              }
              placeholder="mysecret"
            />
          </div>
          <Button type="submit" disabled={updateConfigMutation.isLoading}>
            {updateConfigMutation.isLoading ? "Сохранение..." : "Сохранить"}
          </Button>
        </form>
      </div>

      <Separator />

      <div>
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <Lock className="h-5 w-5 mr-2" />
          Шифрование (Заглушки)
        </h3>
        <div className="space-y-2 text-sm text-muted-foreground">
          <p>• Генерация ключей шифрования - заглушка</p>
          <p>• Обмен публичными ключами - заглушка</p>
          <p>• End-to-end шифрование - заглушка</p>
          <p>• Цифровые подписи - заглушка</p>
        </div>
        <Button variant="outline" className="mt-4" disabled>
          Настроить шифрование
        </Button>
      </div>
    </div>
  );
}

// Главный компонент приложения
export default function App() {
  const auth = useAuth();

  if (auth.status === "loading") {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <Shield className="h-12 w-12 text-primary mx-auto mb-4 animate-pulse" />
          <p className="text-muted-foreground">Загрузка SecureChat...</p>
        </div>
      </div>
    );
  }

  return (
    <Router>
      <div className="min-h-screen bg-background text-foreground">
        <Routes>
          <Route
            path="/login"
            element={
              auth.status === "authenticated" ? (
                <Navigate to="/" replace />
              ) : (
                <LoginForm />
              )
            }
          />
          <Route
            path="/register"
            element={
              auth.status === "authenticated" ? (
                <Navigate to="/" replace />
              ) : (
                <RegisterForm />
              )
            }
          />
          <Route
            path="/"
            element={
              auth.status === "authenticated" ? (
                <ChatInterface />
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
        </Routes>
      </div>
    </Router>
  );
}
