using Npgsql;
using System.Security.Cryptography;
public sealed record PortalUser(int Id,string Name,string Role,int? Organization,int? Warehouse,bool SeeAll,int[] Additional,string PasswordFingerprint);
public sealed record LoginInput(string Username,string Password,string Code,string Invite);
public sealed record EnrollInput(string Challenge,string Code);
public static class PortalAuth
{
    public const string Cookie="__Host-oblik-session";
    private static string Limit(HttpContext context,string name)
    {
        string key=PortalDb.Hash(name.ToLowerInvariant());using var c=PortalDb.Open();
        using var cmd=PortalDb.Command(c,@"INSERT INTO PortalAttempts(IdentityHash,Failures) VALUES(@key,1) ON CONFLICT(IdentityHash) DO UPDATE SET Failures=CASE WHEN PortalAttempts.WindowStart<now()-interval '15 minutes' THEN 1 ELSE PortalAttempts.Failures+1 END,WindowStart=CASE WHEN PortalAttempts.WindowStart<now()-interval '15 minutes' THEN now() ELSE PortalAttempts.WindowStart END RETURNING Failures",("key",key));
        if(Convert.ToInt32(cmd.ExecuteScalar())>10)throw new UnauthorizedAccessException("Забагато спроб. Зачекайте 15 хвилин.");return key;
    }
    public static IResult Login(HttpContext context,LoginInput input)
    {
        string name=(input.Username??"").Trim();if(name.Length>150||(input.Password??"").Length>1024)throw new UnauthorizedAccessException();
        Limit(context,name);
        using var c=PortalDb.Open();using var tx=c.BeginTransaction();
        using var user=PortalDb.Command(c,"SELECT u.id,u.username,u.password,a.InviteHash,a.InviteExpires FROM AppUsers u JOIN PortalAccess a ON a.UserId=u.id WHERE lower(u.username)=lower(@name) AND a.Enabled FOR UPDATE OF a",("name",name));user.Transaction=tx;
        int id;string actual,stored;string? invitation;bool validInvite;
        using(var r=user.ExecuteReader())
        {
            if(!r.Read())throw new UnauthorizedAccessException();id=r.GetInt32(0);actual=r.GetString(1);stored=r.GetString(2);invitation=r.IsDBNull(3)?null:r.GetString(3);validInvite=!r.IsDBNull(4)&&r.GetDateTime(4)>DateTime.UtcNow;if(r.Read())throw new UnauthorizedAccessException();
        }
        if(!Oblik2.PasswordHasher.Verify(input.Password??"",stored,out bool needsUpgrade)||needsUpgrade)throw new UnauthorizedAccessException();
        using var mfa=PortalDb.Command(c,"SELECT Secret,LastStep FROM PortalMfa WHERE UserId=@id FOR UPDATE",("id",id));mfa.Transaction=tx;string? secret=null;long last=-1;using(var r=mfa.ExecuteReader()){if(r.Read()){secret=r.GetString(0);last=r.GetInt64(1);}}
        if(secret==null)
        {
            if(!validInvite||invitation==null||PortalDb.Hash(input.Invite??"")!=invitation)throw new UnauthorizedAccessException("Для першого входу отримайте одноразове запрошення в адміністратора.");
            byte[] raw=RandomNumberGenerator.GetBytes(20);string token=PortalDb.Token();string encrypted=Totp.Protect(raw,id);
            using var create=PortalDb.Command(c,"DELETE FROM PortalChallenges WHERE UserId=@id; INSERT INTO PortalChallenges(TokenHash,UserId,Secret,PasswordHash,Expires) VALUES(@token,@id,@secret,@password,now()+interval '5 minutes'); UPDATE PortalAccess SET InviteHash=NULL,InviteExpires=NULL WHERE UserId=@id",("id",id),("token",PortalDb.Hash(token)),("secret",encrypted),("password",PortalDb.Hash(stored)));create.Transaction=tx;create.ExecuteNonQuery();tx.Commit();
            PortalDb.Audit(context,actual,"Налаштування автентифікатора",true);
            return Results.Json(new{enrollment=true,challenge=token,key=Totp.Base32(raw),account=actual});
        }
        long? step=Totp.Match(Totp.Unprotect(secret,id),input.Code??"",last);if(!step.HasValue)throw new UnauthorizedAccessException("Невірний або вже використаний код. Дочекайтеся нового коду.");
        using(var update=PortalDb.Command(c,"UPDATE PortalMfa SET LastStep=@step WHERE UserId=@id",("step",step.Value),("id",id))){update.Transaction=tx;update.ExecuteNonQuery();}
        string session=CreateSession(c,tx,id,PortalDb.Hash(stored));tx.Commit();PortalDb.Audit(context,actual,"Вхід з MFA",true);SetCookie(context,session);return Results.Json(new{ok=true});
    }
    public static IResult Enroll(HttpContext context,EnrollInput input)
    {
        if((input.Challenge??"").Length!=64)throw new UnauthorizedAccessException();
        using var c=PortalDb.Open();using var tx=c.BeginTransaction();
        using var cmd=PortalDb.Command(c,@"SELECT ch.UserId,ch.Secret,ch.PasswordHash,u.password,u.username FROM PortalChallenges ch JOIN AppUsers u ON u.id=ch.UserId JOIN PortalAccess a ON a.UserId=u.id AND a.Enabled WHERE ch.TokenHash=@hash AND ch.Expires>now() FOR UPDATE OF a,ch",("hash",PortalDb.Hash(input.Challenge)));
        cmd.Transaction=tx;int id;string secret,password,current,name;
        using(var r=cmd.ExecuteReader()){if(!r.Read())throw new UnauthorizedAccessException();id=r.GetInt32(0);secret=r.GetString(1);password=r.GetString(2);current=r.GetString(3);name=r.GetString(4);}
        context.Items["attemptedUser"]=name;Limit(context,name);
        if(password!=PortalDb.Hash(current))throw new UnauthorizedAccessException();long? step=Totp.Match(Totp.Unprotect(secret,id),input.Code??"",-1);if(!step.HasValue)throw new UnauthorizedAccessException("Невірний код автентифікатора.");
        using(var add=PortalDb.Command(c,"INSERT INTO PortalMfa(UserId,Secret,LastStep) VALUES(@id,@secret,@step); DELETE FROM PortalChallenges WHERE UserId=@id",("id",id),("secret",secret),("step",step.Value))){add.Transaction=tx;add.ExecuteNonQuery();}
        string token=CreateSession(c,tx,id,password);tx.Commit();PortalDb.Audit(context,name,"MFA налаштовано, вхід",true);SetCookie(context,token);return Results.Json(new{ok=true});
    }
    private static string CreateSession(NpgsqlConnection c,NpgsqlTransaction tx,int id,string fingerprint)
    {
        string token=PortalDb.Token();using var cmd=PortalDb.Command(c,@"DELETE FROM PortalAttempts WHERE WindowStart<now()-interval '1 day'; DELETE FROM PortalSessions WHERE Expires<now() OR LastSeen<now()-interval '30 minutes'; DELETE FROM PortalChallenges WHERE Expires<now(); INSERT INTO PortalSessions(TokenHash,UserId,PasswordHash,Expires) VALUES(@hash,@id,@password,now()+interval '8 hours')",("hash",PortalDb.Hash(token)),("id",id),("password",fingerprint));cmd.Transaction=tx;cmd.ExecuteNonQuery();
        using var name=PortalDb.Command(c,"SELECT username FROM AppUsers WHERE id=@id",("id",id));name.Transaction=tx;string identity=PortalDb.Hash(((string)name.ExecuteScalar()!).Trim().ToLowerInvariant());
        using var reset=PortalDb.Command(c,"DELETE FROM PortalAttempts WHERE IdentityHash=@key",("key",identity));reset.Transaction=tx;reset.ExecuteNonQuery();return token;
    }
    private static void SetCookie(HttpContext context,string token)=>context.Response.Cookies.Append(Cookie,token,new CookieOptions{HttpOnly=true,Secure=true,SameSite=SameSiteMode.Strict,Path="/",IsEssential=true});
    public static PortalUser Require(HttpContext context)
    {
        if(!context.Request.Cookies.TryGetValue(Cookie,out string? token)||token.Length!=64)throw new UnauthorizedAccessException();
        using var c=PortalDb.Open();using var cmd=PortalDb.Command(c,@"SELECT u.id,u.username,u.role,u.organization_id,u.warehouse_id,COALESCE(u.SeeAllWarehouses,false),COALESCE(u.AdditionalWarehouseIds,ARRAY[]::integer[]),u.password,s.PasswordHash FROM PortalSessions s JOIN AppUsers u ON u.id=s.UserId JOIN PortalAccess a ON a.UserId=u.id AND a.Enabled JOIN PortalMfa m ON m.UserId=u.id WHERE s.TokenHash=@token AND s.Expires>now() AND s.LastSeen>now()-interval '30 minutes'",("token",PortalDb.Hash(token)));
        PortalUser user;using(var r=cmd.ExecuteReader()){if(!r.Read()||PortalDb.Hash(r.GetString(7))!=r.GetString(8))throw new UnauthorizedAccessException();user=new(r.GetInt32(0),r.GetString(1),r.GetString(2),r.IsDBNull(3)?null:r.GetInt32(3),r.IsDBNull(4)?null:r.GetInt32(4),r.GetBoolean(5),r.GetFieldValue<int[]>(6),r.GetString(8));}
        context.Items["attemptedUser"]=user.Name;
        using var touch=PortalDb.Command(c,"UPDATE PortalSessions SET LastSeen=now() WHERE TokenHash=@token",("token",PortalDb.Hash(token)));touch.ExecuteNonQuery();return user;
    }
    public static IResult Logout(HttpContext context)
    {
        var user=Require(context);using var c=PortalDb.Open();using var cmd=PortalDb.Command(c,"DELETE FROM PortalSessions WHERE TokenHash=@token",("token",PortalDb.Hash(context.Request.Cookies[Cookie]!)));cmd.ExecuteNonQuery();PortalDb.Audit(context,user.Name,"Вихід",true);context.Response.Cookies.Delete(Cookie,new CookieOptions{Secure=true,HttpOnly=true,SameSite=SameSiteMode.Strict,Path="/"});return Results.Json(new{ok=true});
    }
}
