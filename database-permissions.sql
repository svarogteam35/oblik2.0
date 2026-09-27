-- TEMPLATE: run by a database administrator in the intended database AFTER schema.sql.
-- Create a dedicated LOGIN role named oblik_portal with a random password separately.
-- Do not use a superuser, table owner, inherited privileged role, or desktop credentials.
-- This script does not create the login or grant membership in any other role.
BEGIN;
GRANT USAGE ON SCHEMA public TO oblik_portal;
GRANT SELECT (id,username,password,role,organization_id,warehouse_id,SeeAllWarehouses,AdditionalWarehouseIds) ON AppUsers TO oblik_portal;
GRANT SELECT ON Warehouses,Organizations,WarehouseViewGrants,UserWarehouseViewPolicy,
 UserWarehouseViewGrants,CategoryCompanyAccess,NomenclatureCategories,Nomenclature,
 InventoryStock,ReceiptRequests,ReceiptRequestItems TO oblik_portal;
GRANT SELECT ON PortalAccess TO oblik_portal;
GRANT UPDATE (InviteHash,InviteExpires) ON PortalAccess TO oblik_portal;
GRANT SELECT,INSERT,UPDATE ON PortalMfa TO oblik_portal;
GRANT SELECT,INSERT,UPDATE,DELETE ON PortalChallenges,PortalSessions,PortalAttempts TO oblik_portal;
GRANT INSERT ON PortalAudit TO oblik_portal;
GRANT USAGE ON SEQUENCE portalaudit_id_seq TO oblik_portal;
COMMIT;
-- No write permission to inventory, users, grants, categories or receipt tables.
-- Review inherited/PUBLIC privileges and database/schema ownership separately.
