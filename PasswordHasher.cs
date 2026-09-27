using System;
using System.Security.Cryptography;
using System.Text;

namespace Oblik2
{
    /// <summary>
    /// Хешування паролів.
    ///
    /// Було: SHA-256 без солі, і до того ж вхід приймав пароль у відкритому
    /// вигляді (`dbPassword == password`). Це означало дві різні проблеми:
    ///
    ///  1. Пароль, записаний у базу як звичайний текст, працював як є. Той, хто
    ///     дістався бази, одразу мав чинні паролі — а люди повторюють паролі
    ///     між системами.
    ///  2. SHA-256 без солі рахується мільярдами за секунду на звичайній
    ///     відеокарті, і однакові паролі дають однаковий хеш. Таблиця з десятка
    ///     хешів розкривається словником за хвилини.
    ///
    /// Стало: PBKDF2-SHA256, 210 000 ітерацій, окрема випадкова сіль на кожного
    /// користувача. Перевірка одного пароля коштує відчутного часу — саме тому
    /// перебір стає невигідним.
    ///
    /// Формат зберігання (один рядок у стовпці password):
    ///     pbkdf2$sha256$&lt;ітерації&gt;$&lt;сіль base64&gt;$&lt;хеш base64&gt;
    ///
    /// Старі SHA-256 хеші приймаються, але лише щоб людина змогла зайти —
    /// одразу після входу запис мовчки переписується на новий формат.
    /// </summary>
    public static class PasswordHasher
    {
        private const string Prefix = "pbkdf2$sha256$";
        private const int Iterations = 210_000;
        private const int SaltBytes = 16;
        private const int HashBytes = 32;

        /// <summary>Створює хеш для збереження в базі.</summary>
        public static string Hash(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(SaltBytes);
            byte[] hash = Derive(password, salt, Iterations);

            return Prefix + Iterations + "$" +
                   Convert.ToBase64String(salt) + "$" +
                   Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Чи підходить пароль до збереженого значення.
        /// needsUpgrade = true, коли запис у старому форматі й його варто
        /// переписати після успішного входу.
        /// </summary>
        public static bool Verify(string password, string stored, out bool needsUpgrade)
        {
            needsUpgrade = false;

            if (string.IsNullOrEmpty(stored)) return false;

            if (stored.StartsWith(Prefix, StringComparison.Ordinal))
                return VerifyPbkdf2(password, stored);

            // Старий формат: 64 шістнадцяткові символи — SHA-256 без солі.
            // Приймаємо, щоб не замкнути людей зовні, і одразу позначаємо на оновлення.
            if (LooksLikeLegacySha256(stored))
            {
                bool ok = FixedTimeEquals(LegacySha256(password), stored);
                if (ok) needsUpgrade = true;
                return ok;
            }

            // Усе інше — це пароль у відкритому вигляді. НЕ приймаємо: саме така
            // «гнучка сумісність» і робила відкритий пароль робочим ключем.
            // Але даємо змогу зайти тим, у кого в базі досі відкритий пароль,
            // і одразу переводимо запис у нормальний формат.
            if (FixedTimeEquals(password, stored))
            {
                needsUpgrade = true;
                return true;
            }

            return false;
        }

        private static bool VerifyPbkdf2(string password, string stored)
        {
            try
            {
                // pbkdf2$sha256$<iter>$<salt>$<hash>
                string[] parts = stored.Split('$');
                if (parts.Length != 5) return false;

                int iterations = int.Parse(parts[2]);
                byte[] salt = Convert.FromBase64String(parts[3]);
                byte[] expected = Convert.FromBase64String(parts[4]);

                byte[] actual = Derive(password, salt, iterations);
                return CryptographicOperations.FixedTimeEquals(actual, expected);
            }
            catch
            {
                return false;
            }
        }

        private static byte[] Derive(string password, byte[] salt, int iterations)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(
                Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(HashBytes);
            }
        }

        private static bool LooksLikeLegacySha256(string value)
        {
            if (value.Length != 64) return false;
            foreach (char c in value)
            {
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex) return false;
            }
            return true;
        }

        private static string LegacySha256(string password)
        {
            using (var sha = SHA256.Create())
            {
                byte[] bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
                var sb = new StringBuilder();
                foreach (byte b in bytes) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        /// <summary>
        /// Порівняння рядків за постійний час. Звичайне порівняння зупиняється
        /// на першому відмінному символі, і за різницею в часі можна підбирати
        /// значення посимвольно.
        /// </summary>
        private static bool FixedTimeEquals(string a, string b)
        {
            byte[] x = Encoding.UTF8.GetBytes(a);
            byte[] y = Encoding.UTF8.GetBytes(b);
            if (x.Length != y.Length) return false;
            return CryptographicOperations.FixedTimeEquals(x, y);
        }

        /// <summary>Проста перевірка якості пароля. Повертає причину відмови або null.</summary>
        public static string? Validate(string password)
        {
            if (password.Length < 8) return "Пароль має бути не коротшим за 8 символів.";

            bool hasLetter = false, hasDigit = false;
            foreach (char c in password)
            {
                if (char.IsLetter(c)) hasLetter = true;
                if (char.IsDigit(c)) hasDigit = true;
            }

            if (!hasLetter || !hasDigit)
                return "Пароль має містити і літери, і цифри.";

            return null;
        }
    }
}
