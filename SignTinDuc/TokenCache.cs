using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    // Bộ nhớ cache cho PKCS#11
    public class TokenCacheItem
    {
        public string Serial { get; set; }
        public string Pkcs11LibPath { get; set; }
        public string Password { get; set; }
        public DateTime LastAccess { get; set; }
    }

    public static class TokenCache
    {
        private static ConcurrentDictionary<string, TokenCacheItem> _cache = new ConcurrentDictionary<string, TokenCacheItem>();
        public static TimeSpan DefaultTtl { get; set; } = TimeSpan.FromMinutes(30);

        public static TokenCacheItem Get(string serial)
        {
            if (string.IsNullOrWhiteSpace(serial)) return null;
            if (_cache.TryGetValue(serial.Trim(), out var item))
            {
                if (DateTime.UtcNow - item.LastAccess < DefaultTtl && File.Exists(item.Pkcs11LibPath))
                {
                    item.LastAccess = DateTime.UtcNow;
                    return item;
                }
                else
                {
                    Remove(serial);
                }
            }
            return null;
        }

        public static void Save(string serial, string pkcs11LibPath, string password)
        {
            if (string.IsNullOrWhiteSpace(serial)) return;
            _cache[serial.Trim()] = new TokenCacheItem
            {
                Serial = serial.Trim(),
                Pkcs11LibPath = pkcs11LibPath,
                Password = password,
                LastAccess = DateTime.UtcNow
            };
        }

        public static void Remove(string serial)
        {
            if (string.IsNullOrWhiteSpace(serial)) return;
            _cache.TryRemove(serial.Trim(), out _);
        }

        public static void CleanupAbsentSerials(IEnumerable<string> serialsPresent)
        {
            var present = new HashSet<string>(serialsPresent.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()));
            foreach (var key in _cache.Keys)
            {
                if (!present.Contains(key))
                    _cache.TryRemove(key, out _);
            }
        }
    }
}
