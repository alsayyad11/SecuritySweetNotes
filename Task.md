# Advanced DataBase Tasks 

## ⪢  T-SQL Programming Basics 

### 1. Variable Declaration and Initialization
```sql
DECLARE @EmployeeName VARCHAR(100) = 'Ahmed Elsayyad'
DECLARE @Salary DECIMAL(10,2), @TaxRate FLOAT, @NetSalary DECIMAL(10,2)
SET @Salary = 7500.00
SET @TaxRate = 0.15
SET @NetSalary = @Salary - (@Salary * @TaxRate)
SELECT @EmployeeName AS Name, @NetSalary AS NetSalary
```

### 2. IF...ELSE with Multiple Conditions
```sql
DECLARE @Grade CHAR(1) = 'B'
DECLARE @GradePoints DECIMAL(3,2)

IF @Grade = 'A'
    SET @GradePoints = 4.0
ELSE IF @Grade = 'B'
    SET @GradePoints = 3.0
ELSE IF @Grade = 'C'
    SET @GradePoints = 2.0
ELSE IF @Grade = 'D'
    SET @GradePoints = 1.0
ELSE
    SET @GradePoints = 0.0

PRINT 'Grade Points: ' + CAST(@GradePoints AS VARCHAR)
```

### 3. WHILE Loop with BREAK and CONTINUE
```sql
DECLARE @Counter INT = 1
DECLARE @Total INT = 0

WHILE @Counter <= 100
BEGIN
    SET @Total = @Total + @Counter
    SET @Counter = @Counter + 1
    
    IF @Counter = 50
        CONTINUE  -- Skip the rest and continue loop
    
    IF @Total > 2000
        BREAK  -- Exit loop
    
    PRINT 'Counter: ' + CAST(@Counter AS VARCHAR) + ', Total: ' + CAST(@Total AS VARCHAR)
END
```

### 4. CASE Expression in SELECT
```sql
SELECT 
    EmployeeID,
    EmployeeName = FirstName + ' ' + LastName,
    Salary,
    SalaryCategory = CASE 
        WHEN Salary >= 8000 THEN 'High Paid'
        WHEN Salary >= 4000 THEN 'Medium Paid'
        WHEN Salary < 4000 THEN 'Low Paid'
        ELSE 'Undefined'
    END,
    DepartmentBonus = CASE DepartmentID
        WHEN 1 THEN Salary * 0.15  -- IT Department
        WHEN 2 THEN Salary * 0.10  -- HR Department
        WHEN 3 THEN Salary * 0.12  -- Finance Department
        ELSE Salary * 0.05
    END
FROM Employees
WHERE Active = 1
```

### 5. Dynamic SQL Execution
```sql
DECLARE @TableName NVARCHAR(50) = 'Employees'
DECLARE @ColumnName NVARCHAR(50) = 'Salary'
DECLARE @Department NVARCHAR(50) = 'IT'
DECLARE @SQL NVARCHAR(1000)

SET @SQL = 'SELECT AVG(' + @ColumnName + ') AS AverageSalary FROM ' + @TableName + 
           ' WHERE Department = @DeptName'

EXEC sp_executesql @SQL, N'@DeptName NVARCHAR(50)', @DeptName = @Department
```

## ⪢  User-Defined Functions 

### 1. Scalar Function - Calculate Age
```sql
CREATE FUNCTION CalculateAge(@BirthDate DATE)
RETURNS INT
AS
BEGIN
    DECLARE @Age INT
    SET @Age = DATEDIFF(YEAR, @BirthDate, GETDATE())
    
    IF (MONTH(@BirthDate) > MONTH(GETDATE()) OR 
        (MONTH(@BirthDate) = MONTH(GETDATE()) AND DAY(@BirthDate) > DAY(GETDATE())))
        SET @Age = @Age - 1
        
    RETURN @Age
END

-- Usage
SELECT dbo.CalculateAge('1990-05-15') AS Age
```

### 2. Scalar Function - Tax Calculation
```sql
CREATE FUNCTION CalculateTax(@Salary DECIMAL(10,2))
RETURNS DECIMAL(10,2)
AS
BEGIN
    DECLARE @Tax DECIMAL(10,2) = 0
    
    IF @Salary > 5000
        SET @Tax = (@Salary - 5000) * 0.20 + 500  -- 20% on amount above 5000 + fixed 500
    ELSE IF @Salary > 3000
        SET @Tax = (@Salary - 3000) * 0.15  -- 15% on amount above 3000
    ELSE IF @Salary > 1500
        SET @Tax = (@Salary - 1500) * 0.10  -- 10% on amount above 1500
    -- Below 1500: No tax
    
    RETURN @Tax
END

-- Usage
SELECT EmployeeName, Salary, dbo.CalculateTax(Salary) AS TaxAmount FROM Employees
```

### 3. Inline Table-Valued Function - Department Employees
```sql
CREATE FUNCTION GetDepartmentEmployees(@DepartmentName VARCHAR(50))
RETURNS TABLE
AS
RETURN (
    SELECT 
        EmployeeID,
        EmployeeName = FirstName + ' ' + LastName,
        Position,
        Salary,
        HireDate
    FROM Employees
    WHERE Department = @DepartmentName 
        AND Active = 1
)

-- Usage
SELECT * FROM dbo.GetDepartmentEmployees('IT')
```

### 4. Inline Table-Valued Function - Employee Search
```sql
CREATE FUNCTION SearchEmployees(@SearchTerm VARCHAR(100))
RETURNS TABLE
AS
RETURN (
    SELECT 
        EmployeeID,
        EmployeeName,
        Department,
        Position,
        Email
    FROM Employees
    WHERE EmployeeName LIKE '%' + @SearchTerm + '%'
        OR Department LIKE '%' + @SearchTerm + '%'
        OR Position LIKE '%' + @SearchTerm + '%'
)

-- Usage
SELECT * FROM dbo.SearchEmployees('Manager')
```

### 5. Multi-Statement Table-Valued Function - Employee Hierarchy
```sql
CREATE FUNCTION GetEmployeeHierarchy(@ManagerID INT)
RETURNS @Hierarchy TABLE (
    EmployeeID INT,
    EmployeeName VARCHAR(100),
    Position VARCHAR(50),
    Level INT,
    HierarchyPath VARCHAR(500)
)
AS
BEGIN
    DECLARE @Level INT = 1
    
    -- Insert direct reports
    INSERT INTO @Hierarchy
    SELECT 
        EmployeeID,
        EmployeeName,
        Position,
        @Level,
        CAST(EmployeeName AS VARCHAR(500))
    FROM Employees
    WHERE ManagerID = @ManagerID
    
    -- Insert second level reports
    INSERT INTO @Hierarchy
    SELECT 
        e.EmployeeID,
        e.EmployeeName,
        e.Position,
        @Level + 1,
        h.HierarchyPath + ' -> ' + e.EmployeeName
    FROM Employees e
    INNER JOIN @Hierarchy h ON e.ManagerID = h.EmployeeID
    
    RETURN
END

-- Usage
SELECT * FROM dbo.GetEmployeeHierarchy(101)
```

## ⪢  Stored Procedures 

### 1. Basic Stored Procedure with Parameters
```sql
CREATE PROCEDURE GetEmployeeByDepartment
    @DepartmentName VARCHAR(50),
    @MinSalary DECIMAL(10,2) = 0
AS
BEGIN
    SELECT 
        EmployeeID,
        EmployeeName,
        Position,
        Salary,
        Email
    FROM Employees
    WHERE Department = @DepartmentName
        AND Salary >= @MinSalary
        AND Active = 1
    ORDER BY Salary DESC
END

-- Execution
EXEC GetEmployeeByDepartment @DepartmentName = 'IT', @MinSalary = 5000
EXEC GetEmployeeByDepartment 'Finance'  -- Using default MinSalary
```

### 2. Stored Procedure with OUTPUT Parameters
```sql
CREATE PROCEDURE GetDepartmentStatistics
    @DepartmentName VARCHAR(50),
    @EmployeeCount INT OUTPUT,
    @TotalSalary DECIMAL(15,2) OUTPUT,
    @AverageSalary DECIMAL(10,2) OUTPUT
AS
BEGIN
    SELECT 
        @EmployeeCount = COUNT(*),
        @TotalSalary = SUM(Salary),
        @AverageSalary = AVG(Salary)
    FROM Employees
    WHERE Department = @DepartmentName
        AND Active = 1
    
    IF @EmployeeCount = 0
    BEGIN
        SET @TotalSalary = 0
        SET @AverageSalary = 0
    END
END

-- Execution with OUTPUT parameters
DECLARE @Count INT, @Total DECIMAL(15,2), @Avg DECIMAL(10,2)
EXEC GetDepartmentStatistics 'IT', @Count OUTPUT, @Total OUTPUT, @Avg OUTPUT
SELECT @Count AS EmployeeCount, @Total AS TotalSalary, @Avg AS AverageSalary
```

### 3. Stored Procedure with Transaction
```sql
CREATE PROCEDURE TransferEmployee
    @EmployeeID INT,
    @NewDepartment VARCHAR(50),
    @NewSalary DECIMAL(10,2)
AS
BEGIN
    SET NOCOUNT ON
    BEGIN TRY
        BEGIN TRANSACTION
        
        -- Update employee department and salary
        UPDATE Employees 
        SET Department = @NewDepartment, 
            Salary = @NewSalary,
            LastModified = GETDATE()
        WHERE EmployeeID = @EmployeeID
        
        -- Log the transfer
        INSERT INTO EmployeeTransfers (EmployeeID, FromDepartment, ToDepartment, TransferDate, NewSalary)
        SELECT 
            @EmployeeID,
            Department,
            @NewDepartment,
            GETDATE(),
            @NewSalary
        FROM Employees 
        WHERE EmployeeID = @EmployeeID
        
        COMMIT TRANSACTION
        PRINT 'Employee transfer completed successfully'
    END TRY
    BEGIN CATCH
        ROLLBACK TRANSACTION
        DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE()
        RAISERROR('Transfer failed: %s', 16, 1, @ErrorMessage)
    END CATCH
END
```

### 4. Stored Procedure with Conditional Logic
```sql
CREATE PROCEDURE UpdateEmployeeSalary
    @EmployeeID INT,
    @IncreasePercentage DECIMAL(5,2),
    @Reason VARCHAR(200)
AS
BEGIN
    DECLARE @CurrentSalary DECIMAL(10,2)
    DECLARE @NewSalary DECIMAL(10,2)
    DECLARE @MaxSalary DECIMAL(10,2) = 20000
    
    -- Get current salary
    SELECT @CurrentSalary = Salary 
    FROM Employees 
    WHERE EmployeeID = @EmployeeID
    
    IF @CurrentSalary IS NULL
    BEGIN
        RAISERROR('Employee not found', 16, 1)
        RETURN
    END
    
    -- Calculate new salary
    SET @NewSalary = @CurrentSalary * (1 + @IncreasePercentage/100)
    
    -- Apply cap if necessary
    IF @NewSalary > @MaxSalary
    BEGIN
        SET @NewSalary = @MaxSalary
        PRINT 'Salary capped at maximum limit of ' + CAST(@MaxSalary AS VARCHAR)
    END
    
    -- Update salary
    UPDATE Employees 
    SET Salary = @NewSalary,
        LastSalaryIncrease = GETDATE()
    WHERE EmployeeID = @EmployeeID
    
    -- Log salary change
    INSERT INTO SalaryHistory (EmployeeID, OldSalary, NewSalary, IncreasePercent, Reason, ChangeDate)
    VALUES (@EmployeeID, @CurrentSalary, @NewSalary, @IncreasePercentage, @Reason, GETDATE())
    
    SELECT 
        @EmployeeID AS EmployeeID,
        @CurrentSalary AS OldSalary,
        @NewSalary AS NewSalary,
        (@NewSalary - @CurrentSalary) AS IncreaseAmount
END
```

### 5. Stored Procedure for Bulk Operations
```sql
CREATE PROCEDURE BulkUpdateSalaries
    @DepartmentName VARCHAR(50),
    @IncreasePercentage DECIMAL(5,2)
AS
BEGIN
    BEGIN TRY
        BEGIN TRANSACTION
        
        -- Update salaries for the department
        UPDATE Employees 
        SET Salary = Salary * (1 + @IncreasePercentage/100),
            LastModified = GETDATE()
        WHERE Department = @DepartmentName
            AND Active = 1
        
        -- Log bulk update
        INSERT INTO BulkSalaryUpdates (Department, IncreasePercentage, AffectedEmployees, UpdateDate)
        SELECT 
            @DepartmentName,
            @IncreasePercentage,
            @@ROWCOUNT,
            GETDATE()
        
        COMMIT TRANSACTION
        
        PRINT 'Successfully updated salaries for ' + CAST(@@ROWCOUNT AS VARCHAR) + ' employees'
    END TRY
    BEGIN CATCH
        ROLLBACK TRANSACTION
        DECLARE @ErrorMsg NVARCHAR(4000) = ERROR_MESSAGE()
        RAISERROR('Bulk update failed: %s', 16, 1, @ErrorMsg)
    END CATCH
END
```

## ⪢  Triggers 

### 1. AFTER INSERT Trigger for Audit
```sql
CREATE TRIGGER trg_AuditEmployeeInsert
ON Employees
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON
    
    INSERT INTO EmployeeAudit (
        EmployeeID, 
        Action, 
        ActionDate, 
        UserName, 
        Details
    )
    SELECT 
        i.EmployeeID,
        'INSERT',
        GETDATE(),
        SYSTEM_USER,
        'New employee: ' + i.FirstName + ' ' + i.LastName + 
        ', Department: ' + i.Department + 
        ', Salary: ' + CAST(i.Salary AS VARCHAR)
    FROM inserted i
END
```

### 2. AFTER UPDATE Trigger for History Tracking
```sql
CREATE TRIGGER trg_TrackEmployeeChanges
ON Employees
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON
    
    -- Track salary changes
    IF UPDATE(Salary)
    BEGIN
        INSERT INTO SalaryHistory (
            EmployeeID, 
            OldSalary, 
            NewSalary, 
            ChangeDate, 
            ChangedBy
        )
        SELECT 
            i.EmployeeID,
            d.Salary,
            i.Salary,
            GETDATE(),
            SYSTEM_USER
        FROM inserted i
        INNER JOIN deleted d ON i.EmployeeID = d.EmployeeID
        WHERE i.Salary <> d.Salary
    END
    
    -- Track department changes
    IF UPDATE(Department)
    BEGIN
        INSERT INTO DepartmentHistory (
            EmployeeID, 
            OldDepartment, 
            NewDepartment, 
            ChangeDate, 
            ChangedBy
        )
        SELECT 
            i.EmployeeID,
            d.Department,
            i.Department,
            GETDATE(),
            SYSTEM_USER
        FROM inserted i
        INNER JOIN deleted d ON i.EmployeeID = d.EmployeeID
        WHERE i.Department <> d.Department
    END
END
```

### 3. INSTEAD OF DELETE Trigger for Soft Delete
```sql
CREATE TRIGGER trg_SoftDeleteEmployee
ON Employees
INSTEAD OF DELETE
AS
BEGIN
    SET NOCOUNT ON
    
    -- Update active status instead of deleting
    UPDATE e
    SET e.Active = 0,
        e.TerminationDate = GETDATE(),
        e.LastModified = GETDATE()
    FROM Employees e
    INNER JOIN deleted d ON e.EmployeeID = d.EmployeeID
    WHERE e.Active = 1
    
    -- Archive the deleted records
    INSERT INTO EmployeeArchive
    SELECT *, GETDATE() 
    FROM deleted
    
    PRINT 'Employees soft deleted successfully'
END
```

### 4. DDL Trigger for Schema Changes
```sql
CREATE TRIGGER trg_AuditSchemaChanges
ON DATABASE
FOR CREATE_TABLE, ALTER_TABLE, DROP_TABLE
AS
BEGIN
    SET NOCOUNT ON
    
    DECLARE @EventData XML = EVENTDATA()
    
    INSERT INTO SchemaAudit (
        EventType,
        ObjectName,
        ObjectType,
        SQLCommand,
        UserName,
        EventDate
    )
    VALUES (
        @EventData.value('(/EVENT_INSTANCE/EventType)[1]', 'NVARCHAR(100)'),
        @EventData.value('(/EVENT_INSTANCE/ObjectName)[1]', 'NVARCHAR(100)'),
        @EventData.value('(/EVENT_INSTANCE/ObjectType)[1]', 'NVARCHAR(100)'),
        @EventData.value('(/EVENT_INSTANCE/TSQLCommand/CommandText)[1]', 'NVARCHAR(MAX)'),
        SYSTEM_USER,
        GETDATE()
    )
    
    PRINT 'Schema change has been audited'
END
```

### 5. Conditional Trigger with Validation
```sql
CREATE TRIGGER trg_ValidateSalaryUpdate
ON Employees
FOR UPDATE
AS
BEGIN
    SET NOCOUNT ON
    
    -- Check if salary is being decreased
    IF EXISTS (
        SELECT 1 
        FROM inserted i
        INNER JOIN deleted d ON i.EmployeeID = d.EmployeeID
        WHERE i.Salary < d.Salary
    )
    BEGIN
        RAISERROR('Salary decrease is not allowed. Use the dedicated procedure for salary adjustments.', 16, 1)
        ROLLBACK TRANSACTION
        RETURN
    END
    
    -- Check if salary exceeds department maximum
    IF EXISTS (
        SELECT 1 
        FROM inserted i
        INNER JOIN Departments d ON i.Department = d.DepartmentName
        WHERE i.Salary > d.MaxSalary
    )
    BEGIN
        RAISERROR('Salary exceeds department maximum limit.', 16, 1)
        ROLLBACK TRANSACTION
        RETURN
    END
END
```

## ⪢  Database Security 

### 1. Creating Logins and Users
```sql
-- Create SQL Server authentication login
CREATE LOGIN Ahmed_Elsayyad WITH PASSWORD = 'SecureP@ss123!'
CREATE LOGIN Mohammed_Elsayyad WITH PASSWORD = 'AnotherP@ss456!'

-- Create database users
CREATE USER Ahmed_Elsayyad FOR LOGIN Ahmed_Elsayyad
CREATE USER Mohammed_Elsayyad FOR LOGIN Mohammed_Elsayyad

-- Create Windows authentication login (if using domain)
CREATE LOGIN [DOMAIN\Ahmed_Elsayyad] FROM WINDOWS
CREATE USER Ahmed_Domain FOR LOGIN [DOMAIN\Ahmed_Elsayyad]
```

### 2. Creating and Managing Roles
```sql
-- Create custom database roles
CREATE ROLE HR_Manager
CREATE ROLE IT_Admin
CREATE ROLE Report_Viewer
CREATE ROLE Data_Entry

-- Add users to roles
ALTER ROLE HR_Manager ADD MEMBER Ahmed_Elsayyad
ALTER ROLE IT_Admin ADD MEMBER Mohammed_Elsayyad
ALTER ROLE Report_Viewer ADD MEMBER Ahmed_Elsayyad
ALTER ROLE db_datareader ADD MEMBER Mohammed_Elsayyad

-- Add users to fixed database roles
EXEC sp_addrolemember 'db_datareader', 'Ahmed_Elsayyad'
EXEC sp_addrolemember 'db_datawriter', 'Mohammed_Elsayyad'
```

### 3. Granting Schema and Object Permissions
```sql
-- Create schemas for better security
CREATE SCHEMA HR AUTHORIZATION dbo
CREATE SCHEMA IT AUTHORIZATION dbo
CREATE SCHEMA Finance AUTHORIZATION dbo

-- Grant schema permissions
GRANT SELECT ON SCHEMA::HR TO HR_Manager
GRANT SELECT, INSERT, UPDATE ON SCHEMA::IT TO IT_Admin
GRANT EXECUTE ON SCHEMA::Finance TO Report_Viewer

-- Grant specific table permissions
GRANT SELECT ON Employees TO Report_Viewer
GRANT SELECT, UPDATE ON Employees TO HR_Manager
GRANT INSERT, UPDATE, DELETE ON IT_Equipment TO IT_Admin

-- Grant column-level permissions
GRANT UPDATE (Email, Phone) ON Employees TO HR_Manager
GRANT UPDATE (Salary) ON Employees TO HR_Manager

-- Grant stored procedure permissions
GRANT EXECUTE ON GetEmployeeDetails TO Report_Viewer
GRANT EXECUTE ON UpdateEmployeeSalary TO HR_Manager
```

### 4. Advanced Security Configuration
```sql
-- Grant with grant option (allow user to grant to others)
GRANT SELECT ON Departments TO Ahmed_Elsayyad WITH GRANT OPTION

-- Deny specific permissions
DENY DELETE ON Employees TO Report_Viewer
DENY ALTER ON SCHEMA::HR TO IT_Admin

-- Grant view definition permissions
GRANT VIEW DEFINITION ON Employees TO HR_Manager
GRANT VIEW DEFINITION ON vw_EmployeeDetails TO Report_Viewer

-- Grant backup permissions (server level)
USE master
GRANT BACKUP DATABASE TO Ahmed_Elsayyad
GRANT BACKUP LOG TO Mohammed_Elsayyad
```

### 5. Security Maintenance and Monitoring
```sql
-- Change login password
ALTER LOGIN Ahmed_Elsayyad WITH PASSWORD = 'NewSecureP@ss789!'

-- Disable and enable logins
ALTER LOGIN Mohammed_Elsayyad DISABLE
ALTER LOGIN Ahmed_Elsayyad ENABLE

-- View user permissions
EXEC sp_helprotect NULL, 'Ahmed_Elsayyad'
EXEC sp_helprolemember 'HR_Manager'

-- Revoke permissions
REVOKE SELECT ON Employees FROM Report_Viewer
REVOKE EXECUTE ON UpdateEmployeeSalary FROM Mohammed_Elsayyad

-- Remove users from roles
EXEC sp_droprolemember 'HR_Manager', 'Ahmed_Elsayyad'
EXEC sp_droprolemember 'IT_Admin', 'Mohammed_Elsayyad'

-- Drop users and logins
DROP USER Ahmed_Elsayyad
DROP USER Mohammed_Elsayyad
DROP LOGIN Ahmed_Elsayyad
DROP LOGIN Mohammed_Elsayyad
```

## ⪢  Transaction Management 

### 1. Basic Transaction with Error Handling
```sql
BEGIN TRY
    BEGIN TRANSACTION
    
    -- Update employee salary
    UPDATE Employees 
    SET Salary = Salary * 1.10,
        LastSalaryIncrease = GETDATE()
    WHERE Department = 'IT'
    
    -- Log the salary increase
    INSERT INTO SalaryIncreaseLog (Department, IncreasePercentage, AffectedEmployees, IncreaseDate)
    VALUES ('IT', 10, @@ROWCOUNT, GETDATE())
    
    COMMIT TRANSACTION
    PRINT 'Salary increase completed successfully'
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0
        ROLLBACK TRANSACTION
    
    DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE()
    DECLARE @ErrorSeverity INT = ERROR_SEVERITY()
    DECLARE @ErrorState INT = ERROR_STATE()
    
    RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState)
END CATCH
```

### 2. Nested Transactions with Save Points
```sql
BEGIN TRANSACTION MainTransaction
    SAVE TRANSACTION SavePoint1
    
    BEGIN TRY
        -- First operation
        UPDATE Accounts 
        SET Balance = Balance - 1000 
        WHERE AccountID = 123
        
        SAVE TRANSACTION SavePoint2
        
        -- Second operation
        UPDATE Accounts 
        SET Balance = Balance + 1000 
        WHERE AccountID = 456
        
        COMMIT TRANSACTION MainTransaction
        PRINT 'Fund transfer completed successfully'
    END TRY
    BEGIN CATCH
        -- Rollback to the last save point
        IF @@TRANCOUNT > 0
        BEGIN
            ROLLBACK TRANSACTION SavePoint2
            PRINT 'Rolled back to SavePoint2'
        END
        
        DECLARE @ErrorMsg NVARCHAR(4000) = ERROR_MESSAGE()
        RAISERROR('Transfer failed: %s', 16, 1, @ErrorMsg)
    END CATCH
```

### 3. Transaction with Isolation Levels
```sql
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE
BEGIN TRANSACTION

    BEGIN TRY
        -- Check current balance
        DECLARE @CurrentBalance DECIMAL(15,2)
        SELECT @CurrentBalance = Balance 
        FROM Accounts 
        WHERE AccountID = 123
        
        -- Perform transfer if sufficient funds
        IF @CurrentBalance >= 5000
        BEGIN
            UPDATE Accounts 
            SET Balance = Balance - 5000 
            WHERE AccountID = 123
            
            UPDATE Accounts 
            SET Balance = Balance + 5000 
            WHERE AccountID = 456
            
            INSERT INTO TransferLog (FromAccount, ToAccount, Amount, TransferDate)
            VALUES (123, 456, 5000, GETDATE())
            
            COMMIT TRANSACTION
            PRINT 'Transfer completed successfully'
        END
        ELSE
        BEGIN
            ROLLBACK TRANSACTION
            RAISERROR('Insufficient funds', 16, 1)
        END
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0
            ROLLBACK TRANSACTION
        
        DECLARE @ErrMsg NVARCHAR(4000) = ERROR_MESSAGE()
        RAISERROR('Transaction failed: %s', 16, 1, @ErrMsg)
    END CATCH
```

### 4. Distributed Transaction
```sql
BEGIN DISTRIBUTED TRANSACTION
    BEGIN TRY
        -- Update local database
        UPDATE LocalDB.dbo.Accounts 
        SET Balance = Balance - 1000 
        WHERE AccountID = 123
        
        -- Update remote database
        UPDATE RemoteServer.RemoteDB.dbo.Accounts 
        SET Balance = Balance + 1000 
        WHERE AccountID = 456
        
        -- Log the transaction
        INSERT INTO TransactionLog (Description, TransactionDate)
        VALUES ('Distributed transfer from Acc123 to Acc456', GETDATE())
        
        COMMIT TRANSACTION
        PRINT 'Distributed transaction completed'
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0
            ROLLBACK TRANSACTION
        
        DECLARE @DistError NVARCHAR(4000) = ERROR_MESSAGE()
        RAISERROR('Distributed transaction failed: %s', 16, 1, @DistError)
    END CATCH
```

### 5. Transaction with Conditional Logic
```sql
CREATE PROCEDURE ProcessEmployeeBonus
    @EmployeeID INT,
    @BonusAmount DECIMAL(10,2)
AS
BEGIN
    SET NOCOUNT ON
    BEGIN TRANSACTION
    
    BEGIN TRY
        DECLARE @CurrentSalary DECIMAL(10,2)
        DECLARE @Department VARCHAR(50)
        
        -- Get employee details
        SELECT 
            @CurrentSalary = Salary,
            @Department = Department
        FROM Employees 
        WHERE EmployeeID = @EmployeeID
        
        IF @CurrentSalary IS NULL
        BEGIN
            ROLLBACK TRANSACTION
            RAISERROR('Employee not found', 16, 1)
            RETURN
        END
        
        -- Check department bonus limit
        DECLARE @DepartmentBonusLimit DECIMAL(10,2)
        SELECT @DepartmentBonusLimit = BonusLimit 
        FROM Departments 
        WHERE DepartmentName = @Department
        
        IF @BonusAmount > @DepartmentBonusLimit
        BEGIN
            ROLLBACK TRANSACTION
            RAISERROR('Bonus amount exceeds department limit', 16, 1)
            RETURN
        END
        
        -- Update salary with bonus
        UPDATE Employees 
        SET Salary = Salary + @BonusAmount,
            LastBonusDate = GETDATE()
        WHERE EmployeeID = @EmployeeID
        
        -- Log bonus payment
        INSERT INTO BonusPayments (EmployeeID, BonusAmount, PaymentDate, ProcessedBy)
        VALUES (@EmployeeID, @BonusAmount, GETDATE(), SYSTEM_USER)
        
        COMMIT TRANSACTION
        PRINT 'Bonus processed successfully'
        
        SELECT 
            @EmployeeID AS EmployeeID,
            @CurrentSalary AS OldSalary,
            @CurrentSalary + @BonusAmount AS NewSalary,
            @BonusAmount AS BonusAmount
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0
            ROLLBACK TRANSACTION
        
        DECLARE @BonusError NVARCHAR(4000) = ERROR_MESSAGE()
        RAISERROR('Bonus processing failed: %s', 16, 1, @BonusError)
    END CATCH
END
```

## ⪢  Data Import/Export 

### 1. Bulk Insert from CSV File
```sql
-- Create staging table
CREATE TABLE Staging_Employees (
    EmployeeID INT,
    FirstName VARCHAR(50),
    LastName VARCHAR(50),
    Department VARCHAR(50),
    Salary DECIMAL(10,2),
    HireDate DATE
)

-- Bulk insert from CSV
BULK INSERT Staging_Employees
FROM 'C:\Data\employees.csv'
WITH (
    FIELDTERMINATOR = ',',
    ROWTERMINATOR = '\n',
    FIRSTROW = 2,
    ERRORFILE = 'C:\Data\errors.log'
)

-- Process staged data
INSERT INTO Employees (EmployeeID, FirstName, LastName, Department, Salary, HireDate)
SELECT EmployeeID, FirstName, LastName, Department, Salary, HireDate
FROM Staging_Employees
WHERE NOT EXISTS (SELECT 1 FROM Employees e WHERE e.EmployeeID = Staging_Employees.EmployeeID)

-- Cleanup
DROP TABLE Staging_Employees
```

### 2. Export Data to CSV using BCP
```sql
-- Export employees data to CSV
EXEC xp_cmdshell 'bcp "SELECT EmployeeID, FirstName, LastName, Department, Salary FROM HR.dbo.Employees" queryout "C:\Export\employees.csv" -c -t, -T -S SERVERNAME'

-- Export with specific query and format
EXEC xp_cmdshell 'bcp "SELECT * FROM HR.dbo.Employees WHERE Department = ''IT'' AND Salary > 5000" queryout "C:\Export\it_employees.csv" -c -t, -T -S SERVERNAME'
```

### 3. Import/Export using OPENROWSET
```sql
-- Import from Excel file
INSERT INTO Employees (FirstName, LastName, Department, Salary)
SELECT FirstName, LastName, Department, Salary
FROM OPENROWSET(
    'Microsoft.ACE.OLEDB.12.0',
    'Excel 12.0;Database=C:\Data\employees.xlsx;HDR=YES',
    'SELECT * FROM [Sheet1$]'
)

-- Export to Excel (using linked server method)
INSERT INTO OPENROWSET(
    'Microsoft.ACE.OLEDB.12.0',
    'Excel 12.0;Database=C:\Export\employee_report.xlsx;',
    'SELECT EmployeeID, FirstName, LastName, Department, Salary FROM Employees'
)
SELECT EmployeeID, FirstName, LastName, Department, Salary
FROM Employees
WHERE Active = 1
```

### 4. Data Import with Transformation
```sql
-- Create staging table for raw data
CREATE TABLE Staging_RawData (
    RawData VARCHAR(MAX)
)

-- Bulk insert raw data
BULK INSERT Staging_RawData
FROM 'C:\Data\raw_employees.txt'
WITH (ROWTERMINATOR = '\n')

-- Transform and insert into main table
INSERT INTO Employees (EmployeeID, FirstName, LastName, Department, Salary)
SELECT 
    CAST(SUBSTRING(RawData, 1, 5) AS INT) AS EmployeeID,
    LTRIM(RTRIM(SUBSTRING(RawData, 6, 25))) AS FirstName,
    LTRIM(RTRIM(SUBSTRING(RawData, 31, 25))) AS LastName,
    LTRIM(RTRIM(SUBSTRING(RawData, 56, 30))) AS Department,
    CAST(SUBSTRING(RawData, 86, 10) AS DECIMAL(10,2)) AS Salary
FROM Staging_RawData
WHERE LEN(RawData) >= 95

-- Cleanup
DROP TABLE Staging_RawData
```

### 5. Automated Data Export Procedure
```sql
CREATE PROCEDURE ExportDepartmentData
    @DepartmentName VARCHAR(50),
    @ExportPath VARCHAR(500)
AS
BEGIN
    DECLARE @FileName VARCHAR(500)
    DECLARE @BCPCommand VARCHAR(1000)
    
    SET @FileName = @ExportPath + '\' + @DepartmentName + '_employees_' + 
                    REPLACE(CONVERT(VARCHAR, GETDATE(), 112), '/', '') + '.csv'
    
    SET @BCPCommand = 'bcp "SELECT EmployeeID, FirstName, LastName, Position, Salary ' +
                      'FROM HR.dbo.Employees WHERE Department = ''' + @DepartmentName + 
                      ''' AND Active = 1" queryout "' + @FileName + '" -c -t, -T -S ' + @@SERVERNAME
    
    EXEC xp_cmdshell @BCPCommand
    
    PRINT 'Data exported to: ' + @FileName
END

-- Usage
EXEC ExportDepartmentData 'IT', 'C:\Exports'
EXEC ExportDepartmentData 'Finance', 'C:\Exports'
```

## ⪢  Backup and Restore 

### 1. Full Database Backup
```sql
-- Full database backup
BACKUP DATABASE HR_Database
TO DISK = 'C:\Backups\HR_Database_Full.bak'
WITH 
    NAME = 'HR_Database-Full Backup',
    DESCRIPTION = 'Full backup of HR database',
    COMPRESSION,
    STATS = 10

-- Backup with encryption (SQL Server 2014+)
BACKUP DATABASE HR_Database
TO DISK = 'C:\Backups\HR_Database_Encrypted.bak'
WITH 
    COMPRESSION,
    ENCRYPTION (
        ALGORITHM = AES_256,
        SERVER CERTIFICATE = BackupCertificate
    ),
    STATS = 5
```

### 2. Differential Backup
```sql
-- Differential backup
BACKUP DATABASE HR_Database
TO DISK = 'C:\Backups\HR_Database_Diff.bak'
WITH 
    DIFFERENTIAL,
    NAME = 'HR_Database-Differential Backup',
    DESCRIPTION = 'Differential backup of HR database',
    COMPRESSION,
    STATS = 10
```

### 3. Transaction Log Backup
```sql
-- Transaction log backup
BACKUP LOG HR_Database
TO DISK = 'C:\Backups\HR_Database_Log.trn'
WITH 
    NAME = 'HR_Database-Transaction Log Backup',
    DESCRIPTION = 'Transaction log backup',
    COMPRESSION,
    STATS = 10

-- Tail-log backup (before restore)
BACKUP LOG HR_Database
TO DISK = 'C:\Backups\HR_Database_TailLog.trn'
WITH 
    NO_TRUNCATE,
    NAME = 'HR_Database-Tail Log Backup'
```

### 4. File and Filegroup Backup
```sql
-- Filegroup backup
BACKUP DATABASE HR_Database
FILEGROUP = 'PRIMARY'
TO DISK = 'C:\Backups\HR_Database_Primary.bak'
WITH 
    NAME = 'HR_Database-PRIMARY Filegroup Backup',
    STATS = 10

-- Multiple file backup
BACKUP DATABASE HR_Database
FILE = 'HR_Data',
FILE = 'HR_Index'
TO DISK = 'C:\Backups\HR_Database_Files.bak'
WITH 
    NAME = 'HR_Database-Data Files Backup',
    STATS = 10
```

### 5. Restore Operations
```sql
-- Restore full backup with recovery
RESTORE DATABASE HR_Database
FROM DISK = 'C:\Backups\HR_Database_Full.bak'
WITH 
    RECOVERY,
    REPLACE,
    STATS = 10

-- Restore with point-in-time recovery
RESTORE DATABASE HR_Database
FROM DISK = 'C:\Backups\HR_Database_Full.bak'
WITH 
    NORECOVERY,
    REPLACE

RESTORE LOG HR_Database
FROM DISK = 'C:\Backups\HR_Database_Log.trn'
WITH 
    RECOVERY,
    STOPAT = '2024-01-15 14:30:00'

-- Restore to new database
RESTORE DATABASE HR_Database_Test
FROM DISK = 'C:\Backups\HR_Database_Full.bak'
WITH 
    MOVE 'HR_Data' TO 'C:\Data\HR_Test_Data.mdf',
    MOVE 'HR_Log' TO 'C:\Data\HR_Test_Log.ldf',
    RECOVERY,
    STATS = 10
```

## ⪢  Replication 

### 1. Configure Distributor
```sql
-- Enable distribution
EXEC sp_adddistributor @distributor = N'DistributorServer'

-- Create distribution database
EXEC sp_adddistributiondb 
    @database = N'distribution',
    @data_folder = N'C:\Data',
    @log_folder = N'C:\Logs'

-- Add publisher
EXEC sp_adddistpublisher 
    @publisher = N'PublisherServer',
    @distribution_db = N'distribution',
    @security_mode = 1
```

### 2. Create Publication
```sql
-- Create transactional publication
EXEC sp_addpublication 
    @publication = N'HR_Publication',
    @description = N'Transactional publication of HR database',
    @repl_freq = N'continuous',
    @status = N'active',
    @allow_push = N'true',
    @allow_pull = N'true',
    @allow_anonymous = N'false',
    @independent_agent = N'true'

-- Add articles (tables) to publication
EXEC sp_addarticle 
    @publication = N'HR_Publication',
    @article = N'Employees',
    @source_owner = N'dbo',
    @source_object = N'Employees',
    @type = N'logbased',
    @description = N'Employees table'

EXEC sp_addarticle 
    @publication = N'HR_Publication',
    @article = N'Departments',
    @source_owner = N'dbo',
    @source_object = N'Departments',
    @type = N'logbased',
    @description = N'Departments table'
```

### 3. Create Push Subscription
```sql
-- Add push subscription
EXEC sp_addsubscription 
    @publication = N'HR_Publication',
    @subscriber = N'SubscriberServer',
    @destination_db = N'HR_Replica',
    @subscription_type = N'Push',
    @sync_type = N'automatic'

-- Add subscription agent
EXEC sp_addpushsubscription_agent 
    @publication = N'HR_Publication',
    @subscriber = N'SubscriberServer',
    @subscriber_db = N'HR_Replica',
    @job_login = NULL,
    @job_password = NULL,
    @subscriber_security_mode = 1
```

### 4. Create Pull Subscription
```sql
-- On subscriber server, create pull subscription
EXEC sp_addpullsubscription 
    @publisher = N'PublisherServer',
    @publication = N'HR_Publication',
    @publisher_db = N'HR_Database',
    @independent_agent = N'True',
    @subscription_type = N'pull',
    @description = N'Pull subscription for HR data'

-- Add pull subscription agent
EXEC sp_addpullsubscription_agent 
    @publisher = N'PublisherServer',
    @publisher_db = N'HR_Database',
    @publication = N'HR_Publication',
    @distributor = N'DistributorServer',
    @distributor_security_mode = 1,
    @distributor_login = N'',
    @distributor_password = N''
```

### 5. Monitor and Manage Replication
```sql
-- Check replication agents status
EXEC sp_help_agent

-- View publication information
EXEC sp_helppublication

-- View subscription information
EXEC sp_helpsubscription

-- Reinitialize subscription
EXEC sp_reinitsubscription 
    @publication = N'HR_Publication',
    @subscriber = N'SubscriberServer',
    @destination_db = N'HR_Replica'

-- Remove subscription
EXEC sp_dropsubscription 
    @publication = N'HR_Publication',
    @subscriber = N'SubscriberServer',
    @destination_db = N'HR_Replica'

-- Remove publication
EXEC sp_droppublication @publication = N'HR_Publication'
```

## ⪢  Database Mirroring 

### 1. Configure Database for Mirroring
```sql
-- Set recovery model to FULL
ALTER DATABASE HR_Database SET RECOVERY FULL

-- Create endpoint for mirroring
CREATE ENDPOINT MirroringEndpoint
    STATE = STARTED
    AS TCP (LISTENER_PORT = 7024)
    FOR DATABASE_MIRRORING (ROLE = ALL)

-- Backup database for mirroring
BACKUP DATABASE HR_Database 
TO DISK = 'C:\Backups\HR_Database_ForMirroring.bak'

BACKUP LOG HR_Database 
TO DISK = 'C:\Backups\HR_Database_ForMirroring.trn'
```

### 2. Establish Mirroring Session
```sql
-- On principal server
ALTER DATABASE HR_Database SET PARTNER = 'TCP://MirrorServer:7024'

-- On mirror server (restore with NORECOVERY)
RESTORE DATABASE HR_Database 
FROM DISK = 'C:\Backups\HR_Database_ForMirroring.bak'
WITH NORECOVERY

RESTORE LOG HR_Database 
FROM DISK = 'C:\Backups\HR_Database_ForMirroring.trn'
WITH NORECOVERY

-- On mirror server, set partner
ALTER DATABASE HR_Database SET PARTNER = 'TCP://PrincipalServer:7024'
```

### 3. Configure High Safety Mode with Witness
```sql
-- Add witness server (on principal)
ALTER DATABASE HR_Database SET WITNESS = 'TCP://WitnessServer:7024'

-- Set high safety mode (synchronous)
ALTER DATABASE HR_Database SET SAFETY FULL

-- Check mirroring status
SELECT 
    database_id,
    mirroring_state_desc,
    mirroring_safety_level_desc,
    mirroring_partner_name,
    mirroring_witness_name
FROM sys.database_mirroring
WHERE database_id = DB_ID('HR_Database')
```

### 4. Manual Failover
```sql
-- On principal server, initiate manual failover
ALTER DATABASE HR_Database SET PARTNER FAILOVER

-- Check roles after failover
SELECT 
    DB_NAME(database_id) AS DatabaseName,
    mirroring_role_desc,
    mirroring_state_desc
FROM sys.database_mirroring
WHERE database_id = DB_ID('HR_Database')
```

### 5. Monitor and Manage Mirroring
```sql
-- Check mirroring status
EXEC sp_dbmmonitorresults 'HR_Database'

-- Pause mirroring
ALTER DATABASE HR_Database SET PARTNER SUSPEND

-- Resume mirroring
ALTER DATABASE HR_Database SET PARTNER RESUME

-- Remove mirroring
ALTER DATABASE HR_Database SET PARTNER OFF

-- Remove witness
ALTER DATABASE HR_Database SET WITNESS OFF
```

## ⪢  Log Shipping 

### 1. Configure Log Shipping Primary
```sql
-- Enable log shipping on primary database
EXEC master.dbo.sp_add_log_shipping_primary_database 
    @database = N'HR_Database',
    @backup_directory = N'C:\LS_Backup',
    @backup_share = N'\\Server\LS_Backup',
    @backup_job_name = N'LSBackup_HR_Database',
    @backup_retention_period = 4320,
    @backup_threshold = 60,
    @history_retention_period = 5760,
    @threshold_alert_enabled = 1

-- Add primary backup job
EXEC msdb.dbo.sp_add_schedule 
    @schedule_name = N'LSBackupSchedule_HR_Database',
    @freq_type = 4,
    @freq_interval = 1,
    @freq_subday_type = 4,
    @freq_subday_interval = 15,
    @active_start_time = 0

EXEC msdb.dbo.sp_attach_schedule 
    @job_name = N'LSBackup_HR_Database',
    @schedule_name = N'LSBackupSchedule_HR_Database'
```

### 2. Configure Log Shipping Secondary
```sql
-- Add secondary database
EXEC master.dbo.sp_add_log_shipping_secondary_primary 
    @primary_server = N'PrimaryServer',
    @primary_database = N'HR_Database',
    @backup_source_directory = N'\\Server\LS_Backup',
    @backup_destination_directory = N'C:\LS_Copy',
    @copy_job_name = N'LSCopy_HR_Database',
    @restore_job_name = N'LSRestore_HR_Database',
    @file_retention_period = 4320

-- Add secondary database
EXEC master.dbo.sp_add_log_shipping_secondary_database 
    @secondary_database = N'HR_Database',
    @primary_server = N'PrimaryServer',
    @primary_database = N'HR_Database',
    @restore_delay = 0,
    @restore_mode = 0,
    @disconnect_users = 0,
    @restore_threshold = 45,
    @threshold_alert_enabled = 1
```

### 3. Monitor Log Shipping
```sql
-- Check log shipping status
SELECT 
    primary_database,
    secondary_database,
    last_backup_file,
    last_copied_file,
    last_restored_file,
    last_restored_latency
FROM msdb.dbo.log_shipping_monitor_primary

SELECT 
    secondary_server,
    secondary_database,
    last_copied_file,
    last_restored_file,
    last_restored_date,
    restore_lag
FROM msdb.dbo.log_shipping_monitor_secondary

-- Check log shipping jobs status
EXEC msdb.dbo.sp_help_job @job_name = 'LSBackup_HR_Database'
EXEC msdb.dbo.sp_help_job @job_name = 'LSCopy_HR_Database'
EXEC msdb.dbo.sp_help_job @job_name = 'LSRestore_HR_Database'
```

### 4. Failover to Secondary
```sql
-- On primary: Take final transaction log backup
BACKUP LOG HR_Database 
TO DISK = 'C:\LS_Backup\HR_Database_Failover.trn'

-- On secondary: Restore all remaining logs
RESTORE LOG HR_Database 
FROM DISK = 'C:\LS_Copy\HR_Database_Failover.trn'
WITH RECOVERY

-- Update applications to point to secondary server
-- The secondary database is now the primary
```

### 5. Remove Log Shipping
```sql
-- Remove secondary database
EXEC master.dbo.sp_delete_log_shipping_secondary_database 
    @secondary_database = N'HR_Database'

-- Remove secondary primary
EXEC master.dbo.sp_delete_log_shipping_secondary_primary 
    @primary_server = N'PrimaryServer',
    @primary_database = N'HR_Database'

-- Remove primary database
EXEC master.dbo.sp_delete_log_shipping_primary_database 
    @database = N'HR_Database'

-- Remove jobs
EXEC msdb.dbo.sp_delete_job @job_name = 'LSBackup_HR_Database'
EXEC msdb.dbo.sp_delete_job @job_name = 'LSCopy_HR_Database'
EXEC msdb.dbo.sp_delete_job @job_name = 'LSRestore_HR_Database'
```
