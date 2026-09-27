using System.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;
public static class Totp
{
    public static byte[] Key=Array.Empty<byte>();
    public static string Protect(byte[] secret,int user)
    {byte[] nonce=RandomNumberGenerator.GetBytes(12),tag=new byte[16],cipher=new byte[secret.Length];using var aes=new AesGcm(Key,16);aes.Encrypt(nonce,secret,cipher,tag,Encoding.UTF8.GetBytes(user.ToString()));return Convert.ToBase64String(nonce.Concat(tag).Concat(cipher).ToArray());}
    public static byte[] Unprotect(string text,int user)
    {byte[] bytes=Convert.FromBase64String(text),plain=new byte[bytes.Length-28];using var aes=new AesGcm(Key,16);aes.Decrypt(bytes[..12],bytes[28..],bytes[12..28],plain,Encoding.UTF8.GetBytes(user.ToString()));return plain;}
    public static string Base32(byte[] bytes)
    {const string alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";var result=new StringBuilder();int buffer=0,bits=0;foreach(byte b in bytes){buffer=(buffer<<8)|b;bits+=8;while(bits>=5){bits-=5;result.Append(alphabet[(buffer>>bits)&31]);}}if(bits>0)result.Append(alphabet[(buffer<<(5-bits))&31]);return result.ToString();}
    public static string Code(byte[] secret,long step)
    {Span<byte> counter=stackalloc byte[8];BinaryPrimitives.WriteInt64BigEndian(counter,step);byte[] hash=HMACSHA1.HashData(secret,counter);int offset=hash[^1]&15;int value=BinaryPrimitives.ReadInt32BigEndian(hash.AsSpan(offset,4))&int.MaxValue;return (value%1000000).ToString("D6");}
    public static long? Match(byte[] secret,string code,long lastStep)
    {if(code.Length!=6||code.Any(c=>c<'0'||c>'9'))return null;long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds()/30;foreach(long step in new[]{now,now-1,now+1})if(step>lastStep&&CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Code(secret,step)),Encoding.ASCII.GetBytes(code)))return step;return null;}
}
