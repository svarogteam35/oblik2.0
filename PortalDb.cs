using Npgsql;
using System.Security.Cryptography;
using System.Text;
public static class PortalDb
{
    public static string Connection="";
    public static NpgsqlConnection Open(){var c=new NpgsqlConnection(Connection);c.Open();return c;}
    public static NpgsqlCommand Command(NpgsqlConnection c,string sql,params (string,object?)[] args){var cmd=new NpgsqlCommand(sql,c){CommandTimeout=20};foreach(var (name,value) in args)cmd.Parameters.AddWithValue(name,value??DBNull.Value);return cmd;}
    public static string Hash(string text)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    public static string Token()=>Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public static void Audit(HttpContext context,string actor,string action,bool success,int? org=null,int? warehouse=null,int? count=null,string details="")
    {
        using var c=Open();using var cmd=Command(c,"INSERT INTO PortalAudit(Actor,Event,Success,Ip,UserAgent,OrganizationId,WarehouseId,ResultCount,Details) VALUES(@actor,@event,@ok,@ip,@ua,@org::integer,@wh::integer,@count::integer,@details)",("actor",actor[..Math.Min(actor.Length,150)]),("event",action),("ok",success),("ip",context.Connection.RemoteIpAddress?.ToString()??""),("ua",context.Request.Headers.UserAgent.ToString()[..Math.Min(context.Request.Headers.UserAgent.ToString().Length,500)]),("org",org),("wh",warehouse),("count",count),("details",details));cmd.ExecuteNonQuery();
    }
    public static List<Dictionary<string,object?>> Rows(NpgsqlCommand cmd)
    {using var r=cmd.ExecuteReader();var rows=new List<Dictionary<string,object?>>();while(r.Read()){var row=new Dictionary<string,object?>();for(int i=0;i<r.FieldCount;i++)row[r.GetName(i)]=r.IsDBNull(i)?null:r.GetValue(i);rows.Add(row);}return rows;}
}
