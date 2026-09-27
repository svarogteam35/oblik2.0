using Npgsql;
public static class PortalData
{
    // Recomputed for every request. No client-selected company grants access by itself.
    public static int[] Allowed(PortalUser user)
    {
        using var c=PortalDb.Open();
        using var cmd=PortalDb.Command(c,@"WITH RECURSIVE grants AS (
          SELECT g.WarehouseId,g.IncludeChildren FROM WarehouseViewGrants g WHERE g.ViewerOrgId=@org::integer AND NOT EXISTS(SELECT 1 FROM UserWarehouseViewPolicy p WHERE p.UserId=@id)
          UNION SELECT g.WarehouseId,g.IncludeChildren FROM UserWarehouseViewGrants g WHERE g.UserId=@id),
          foreign_allowed(Id,Children) AS (SELECT WarehouseId,IncludeChildren FROM grants UNION SELECT w.Id,true FROM Warehouses w JOIN foreign_allowed a ON w.parent_id=a.Id AND a.Children),
          assigned(Id) AS (SELECT w.Id FROM Warehouses w WHERE w.organization_id=@org::integer AND (w.Id=@warehouse::integer OR w.Id=ANY(@extra)) UNION SELECT w.Id FROM Warehouses w JOIN assigned a ON w.parent_id=a.Id WHERE w.organization_id=@org::integer),
          mains(Id) AS (SELECT w.Id FROM Warehouses w WHERE w.organization_id=@org::integer AND w.IsMain)
          SELECT w.Id FROM Warehouses w WHERE @super OR w.Id IN(SELECT Id FROM foreign_allowed) OR (w.organization_id=@org::integer AND (@all OR (@chief AND w.Id IN(SELECT Id FROM mains)) OR (@keeper AND (w.Id IN(SELECT Id FROM assigned) OR w.IsMain))))",("org",user.Organization),("id",user.Id),("warehouse",user.Warehouse),("extra",user.Additional),("super",user.Role=="SuperAdmin"),("all",user.Role is "OrgAdmin" or "Observer"||(user.SeeAll&&user.Role is not ("ChiefStorekeeper" or "WarehouseAdmin" or "Storekeeper"))),("chief",user.Role is "ChiefStorekeeper" or "WarehouseAdmin"),("keeper",user.Role=="Storekeeper"));
        using var r=cmd.ExecuteReader();var ids=new List<int>();while(r.Read())ids.Add(r.GetInt32(0));return ids.ToArray();
    }
    public static object Filters(HttpContext context,PortalUser user)
    {
        int[] allowed=Allowed(user);using var c=PortalDb.Open();using var cmd=PortalDb.Command(c,"SELECT o.Id AS organizationid,o.Name AS organization,w.Id AS warehouseid,w.Name AS warehouse,w.parent_id AS parentid,w.IsMain AS main FROM Warehouses w JOIN Organizations o ON o.Id=w.organization_id WHERE w.Id=ANY(@ids) ORDER BY o.Name,w.IsMain DESC,w.Name",("ids",allowed));var rows=PortalDb.Rows(cmd);PortalDb.Audit(context,user.Name,"Перегляд доступних складів",true,count:rows.Count);return new{user=user.Name,warehouses=rows};
    }
    public static object Items(HttpContext context,PortalUser user,int org,int warehouse,bool future,string search,int page)
    {
        int[] allowed=Allowed(user);page=Math.Clamp(page,0,100000);search=(search??"");if(search.Length>150)search=search[..150];
        using var c=PortalDb.Open();using var scope=PortalDb.Command(c,"SELECT Id FROM Warehouses WHERE organization_id=@org AND Id=ANY(@ids) AND (@wh=0 OR Id=@wh)",("org",org),("ids",allowed),("wh",warehouse));
        var ids=new List<int>();using(var r=scope.ExecuteReader())while(r.Read())ids.Add(r.GetInt32(0));
        if(ids.Count==0){PortalDb.Audit(context,user.Name,"Відмовлено в доступі до складу",false,org,warehouse);throw new UnauthorizedAccessException();}
        string deny=@"WITH RECURSIVE blocked(Id) AS (SELECT CategoryId FROM CategoryCompanyAccess WHERE OrganizationId=@viewer::integer AND NOT Allowed UNION SELECT c.Id FROM NomenclatureCategories c JOIN blocked b ON c.ParentId=b.Id) ";
        string sql=future?@"SELECT r.RequestNumber AS document,w.Name AS warehouse,i.ProductName AS product,i.DeclaredQuantity AS quantity,i.Unit AS unit,i.ArrivalDate AS date,i.SerialNumber AS serial,i.InventoryNumber AS inventory,i.Feature AS feature,i.Price AS price,CASE WHEN r.OnBalance THEN 'На обліку' ELSE 'Фактично в наявності' END AS balance FROM ReceiptRequests r JOIN ReceiptRequestItems i ON i.RequestId=r.Id JOIN Warehouses w ON w.Id=r.WarehouseId LEFT JOIN Nomenclature n ON n.Id=i.NomenclatureId WHERE r.Status='Заплановано' AND r.WarehouseId=ANY(@ids) AND (n.category_id IS NULL OR n.category_id NOT IN(SELECT Id FROM blocked)) AND (i.ProductName ILIKE @search OR i.SerialNumber ILIKE @search OR i.InventoryNumber ILIKE @search) ORDER BY i.ArrivalDate,r.Id,i.Id LIMIT 101 OFFSET @offset":@"SELECT s.Id AS id,w.Name AS warehouse,n.Name AS product,s.Quantity AS quantity,n.Unit AS unit,s.ArrivalDate AS date,s.SerialNumber AS serial,s.InventoryNumber AS inventory,s.Feature AS feature,s.Price AS price,CASE WHEN s.OnBalance THEN 'На обліку' ELSE 'Фактично в наявності' END AS balance,c.Name AS category FROM InventoryStock s JOIN Nomenclature n ON n.Id=s.NomenclatureId JOIN Warehouses w ON w.Id=s.WarehouseId LEFT JOIN NomenclatureCategories c ON c.Id=n.category_id WHERE s.WarehouseId=ANY(@ids) AND s.Quantity>0 AND s.Status IN('На складі','У ремонті','Потребує ремонту') AND (n.category_id IS NULL OR n.category_id NOT IN(SELECT Id FROM blocked)) AND (n.Name ILIKE @search OR s.SerialNumber ILIKE @search OR s.InventoryNumber ILIKE @search) ORDER BY n.Name,s.Id LIMIT 101 OFFSET @offset";
        using var cmd=PortalDb.Command(c,deny+sql,("viewer",user.Organization),("ids",ids.ToArray()),("search","%"+search.Replace("\\","\\\\").Replace("%","\\%").Replace("_","\\_")+"%"),("offset",page*100));var rows=PortalDb.Rows(cmd);bool more=rows.Count>100;if(more)rows.RemoveAt(100);PortalDb.Audit(context,user.Name,future?"Перегляд майбутніх надходжень":"Перегляд залишків",true,org,warehouse,rows.Count,$"Сторінка {page+1}");return new{rows,more,page};
    }
}
