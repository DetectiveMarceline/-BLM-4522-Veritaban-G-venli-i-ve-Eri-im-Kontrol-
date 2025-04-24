# -BLM-4522-Veritaban-G-venli-i-ve-Eri-im-Kontrol-
Veritabanı Güvenliği ve Erişim Kontrolü

# Adım 1: SQL Server Authentication ile Erişim Yönetimi
CREATE LOGIN HW_SalesUser WITH PASSWORD = 'StrongPassword123!';
USE SalesDB;
CREATE USER HW_SalesUser FOR LOGIN HW_SalesUser;
CREATE ROLE HW_SalesStaffRole;
GRANT SELECT ON dbo.Customers TO HW_SalesStaffRole;
GRANT SELECT, INSERT, UPDATE ON dbo.Sales TO HW_SalesStaffRole;
ALTER ROLE HW_SalesStaffRole ADD MEMBER HW_SalesUser;

# Adım 2: Windows Authentication ile Erişim Yönetimi
USE SalesDB;

-- Windows kullanıcısını kontrol et ve oluştur
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'MARCELINE\maede')
BEGIN
    CREATE USER [MARCELINE\maede] FOR LOGIN [MARCELINE\maede];
END

-- Sadece okuma izni olan rol oluşturma (veya var olan role ekleme)
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'HW_ReadOnlyRole')
BEGIN
    CREATE ROLE HW_ReadOnlyRole;
    GRANT SELECT ON SCHEMA::dbo TO HW_ReadOnlyRole;
END

-- Windows kullanıcısını role ekleme
ALTER ROLE HW_ReadOnlyRole ADD MEMBER [MARCELINE\maede];

-- Kullanıcının role eklendiğini doğrulama
SELECT 
    DP1.name AS DatabaseRoleName,
    DP2.name AS DatabaseUserName
FROM sys.database_role_members DRM
JOIN sys.database_principals DP1 ON DRM.role_principal_id = DP1.principal_id
JOIN sys.database_principals DP2 ON DRM.member_principal_id = DP2.principal_id
WHERE DP1.name = 'HW_ReadOnlyRole';

# Adım 3: Veri Şifreleme (TDE)

-- Master key oluşturma
USE master;
IF NOT EXISTS (SELECT * FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
BEGIN
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'HW_MasterKey_StrongPassword123!';
END
ELSE
    PRINT 'Master key already exists';

-- Sertifika oluşturma
IF NOT EXISTS (SELECT * FROM sys.certificates WHERE name = 'HW_SalesDBCert')
BEGIN
    CREATE CERTIFICATE HW_SalesDBCert WITH SUBJECT = 'Certificate for TDE on SalesDB Homework';
END
ELSE
    PRINT 'Certificate already exists';

-- Veritabanı şifreleme anahtarı oluşturma
USE SalesDB;
IF NOT EXISTS (SELECT * FROM sys.dm_database_encryption_keys WHERE database_id = DB_ID('SalesDB'))
BEGIN
    CREATE DATABASE ENCRYPTION KEY
    WITH ALGORITHM = AES_256
    ENCRYPTION BY SERVER CERTIFICATE HW_SalesDBCert;

    -- Şifrelemeyi etkinleştirme
    ALTER DATABASE SalesDB
    SET ENCRYPTION ON;
END
ELSE
    PRINT 'Database encryption already configured';

-- Şifreleme durumunu kontrol etme
SELECT DB_NAME(database_id) AS DatabaseName, 
       encryption_state, 
       percent_complete, 
       key_algorithm, 
       key_length
FROM sys.dm_database_encryption_keys;

# Adım 4: SQL Injection Koruması

-- SQL Injection test tablosu oluşturma
USE SalesDB;
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'HW_UserAccounts')
BEGIN
    CREATE TABLE HW_UserAccounts (
        UserID INT PRIMARY KEY IDENTITY(1,1),
        Username NVARCHAR(50) NOT NULL,
        Password NVARCHAR(100) NOT NULL
    );
    
    -- Örnek veri ekleme
    INSERT INTO HW_UserAccounts (Username, Password)
    VALUES ('admin', 'admin123'), ('user1', 'password123');
END

-- Güvenlik açığı olan sorgu örneği (SADECE GÖSTERİM AMAÇLI - ÜRETİM ORTAMINDA KULLANMAYIN)
PRINT 'VULNERABLE QUERY EXAMPLE - FOR DEMONSTRATION ONLY:';
PRINT 'DECLARE @UserInput NVARCHAR(100) = ''user1'' OR 1=1--'';';
PRINT 'DECLARE @SqlQuery NVARCHAR(500) = ''SELECT * FROM HW_UserAccounts WHERE Username = '''''' + @UserInput + '''''''';';
PRINT 'EXEC(@SqlQuery);';
PRINT '-- This would return all records regardless of username';

-- Güvenli stored procedure oluşturma
IF NOT EXISTS (SELECT * FROM sys.procedures WHERE name = 'HW_GetUserByUsername')
BEGIN
    EXEC('
    CREATE PROCEDURE HW_GetUserByUsername
        @Username NVARCHAR(50)
    AS
    BEGIN
        SELECT * FROM HW_UserAccounts WHERE Username = @Username;
    END
    ');
END

-- Güvenli sorgu örneği
PRINT 'Safe way to query:';
PRINT 'EXEC HW_GetUserByUsername @Username = ''user1'';';

-- sp_executesql ile parametreli sorgu kullanımı (diğer güvenli yöntem)
PRINT 'Another safe method using sp_executesql:';
PRINT 'DECLARE @SQL NVARCHAR(1000);';
PRINT 'DECLARE @Username NVARCHAR(50) = ''user1'';';
PRINT 'SET @SQL = N''SELECT * FROM HW_UserAccounts WHERE Username = @User'';';
PRINT 'EXEC sp_executesql @SQL, N''@User NVARCHAR(50)'', @User = @Username;';

# Adım 5: Denetim Günlükleri (Audit Logs)

-- Var olan denetim nesnelerini temizleme
USE master;

IF EXISTS (SELECT * FROM sys.database_audit_specifications WHERE name = 'HW_SalesDBDatabaseAuditSpec')
BEGIN
    USE SalesDB;
    ALTER DATABASE AUDIT SPECIFICATION HW_SalesDBDatabaseAuditSpec WITH (STATE = OFF);
    DROP DATABASE AUDIT SPECIFICATION HW_SalesDBDatabaseAuditSpec;
END

IF EXISTS (SELECT * FROM sys.server_audits WHERE name = 'HW_SalesDBServerAudit')
BEGIN
    ALTER SERVER AUDIT HW_SalesDBServerAudit WITH (STATE = OFF);
    DROP SERVER AUDIT HW_SalesDBServerAudit;
END

-- Sunucu denetimi oluşturma
CREATE SERVER AUDIT HW_SalesDBServerAudit 
TO FILE (FILEPATH = 'C:\temp\');

-- Denetimi etkinleştirme
ALTER SERVER AUDIT HW_SalesDBServerAudit WITH (STATE = ON);

-- Veritabanı denetim spesifikasyonu oluşturma
USE SalesDB;
CREATE DATABASE AUDIT SPECIFICATION HW_SalesDBDatabaseAuditSpec
FOR SERVER AUDIT HW_SalesDBServerAudit
ADD (SELECT ON dbo.Customers BY dbo);

-- Veritabanı denetimini etkinleştirme
ALTER DATABASE AUDIT SPECIFICATION HW_SalesDBDatabaseAuditSpec
WITH (STATE = ON);

# Adım 6: Güvenlik Uygulamalarının Test Edilmesi

-- Güvenlik test scripti
PRINT '--- SECURITY TESTING SCRIPT ---';
PRINT '';

-- Test 1: Kullanıcı rolleri ve izinleri doğrulama
PRINT '1. To verify user roles and permissions:';
PRINT 'SELECT DP1.name AS DatabaseRoleName, DP2.name AS DatabaseUserName';
PRINT 'FROM sys.database_role_members DRM';
PRINT 'JOIN sys.database_principals DP1 ON DRM.role_principal_id = DP1.principal_id';
PRINT 'JOIN sys.database_principals DP2 ON DRM.member_principal_id = DP2.principal_id;';
PRINT '';

-- Test 2: Şifreleme durumunu doğrulama
PRINT '2. To verify database encryption status:';
PRINT 'SELECT DB_NAME(database_id) AS DatabaseName, encryption_state,';
PRINT '       CASE encryption_state';
PRINT '           WHEN 0 THEN ''No database encryption key present, no encryption''';
PRINT '           WHEN 1 THEN ''Unencrypted''';
PRINT '           WHEN 2 THEN ''Encryption in progress''';
PRINT '           WHEN 3 THEN ''Encrypted''';
PRINT '           WHEN 4 THEN ''Key change in progress''';
PRINT '           WHEN 5 THEN ''Decryption in progress''';
PRINT '           WHEN 6 THEN ''Protection change in progress''';
PRINT '       END AS EncryptionStateDesc,';
PRINT '       percent_complete, key_algorithm, key_length';
PRINT 'FROM sys.dm_database_encryption_keys;';
PRINT '';

-- Test 3: SQL Injection korumasını test etme
PRINT '3. To test SQL injection protection:';
PRINT '-- Connect as HW_SalesUser and try both methods:';
PRINT '-- a) Try the vulnerable approach (in a controlled environment only)';
PRINT '-- b) Use the safe parameterized query';
PRINT '';

-- Test 4: Denetimin çalıştığını doğrulama
PRINT '4. To verify audit is working:';
PRINT '-- Perform some operations on the audited tables then check logs';
PRINT 'SELECT TOP 10 event_time, action_id, server_principal_name, database_name';
PRINT 'FROM sys.fn_get_audit_file(''C:\temp\*.sqlaudit'', DEFAULT, DEFAULT)';
PRINT 'ORDER BY event_time DESC;';
