import psycopg2
import config


def create_tables():
    commands = (
        """
        Create Table UserStatus
            (
            ID SERIAL PRIMARY KEY,
            UserUUID VARCHAR(200),
            RelationshipID VarChar(100)	,
            StatusID INT,
            Created_Date Date
            )	
        """,
        """ 	
        Create Table StatusMaster
        (
        ID SERIAL PRIMARY KEY,
        StatusCode CHAR(50),
        StatusDetails VarChar(200),
        Created_Date Date,
        IsActive Boolean	
        )
        """)

    conn = None
    try:
        # read the connection parameters
        params = config()
        # connect to the PostgreSQL server
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        # create table one by one
        for command in commands:
            cur.execute(command)
        # close communication with the PostgreSQL database server
        cur.close()
        # commit the changes
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()


def insert_data():
    commands = (
        """
       INSERT INTO statusmaster(userstatuscode, userstatusdescription, createddate, isactive)
       VALUES ('UNE', 'User has nopipt enrolled', Now(),True)	
       INSERT INTO statusmaster(userstatuscode, userstatusdescription, createddate, isactive)
       Values('UHE','User has enrolled',Now(),True)
       INSERT INTO statusmaster(userstatuscode, userstatusdescription, createddate, isactive)
       Values('UHA','User has activated',Now(),True)
       
       """)

    conn = None
    try:
        # read the connection parameters
        params = config()
        # connect to the PostgreSQL server
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        # create table one by one
        for command in commands:
            cur.execute(command)
        # close communication with the PostgreSQL database server
        cur.close()
        # commit the changes
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()


def get_user_status_by_uuid(user_uuid):
    conn = None
    try:
        # read connection parameters
        params = config.config()

        # connect to the PostgreSQL server
        conn = psycopg2.connect(**params)

        # create a cursor
        cur = conn.cursor()
        cur.callproc("func_GetUserStatusByUUId", [user_uuid])
        user_data = cur.fetchmany()
        user_status_code = None
        requester_Id = None
        status_details = None
        if not user_data:
            return user_status_code, requester_Id, status_details
        for row in user_data:
            user_status_code = row[0].strip()
            requester_Id = row[1]
            status_details = row[2].strip()
        # close the communication with the PostgreSQL
        cur.close()
        return user_status_code, requester_Id, status_details
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()


def get_userid(relationship_did):
    conn = None
    try:
        # read connection parameters
        params = config.config()

        # connect to the PostgreSQL server
        conn = psycopg2.connect(**params)

        # create a cursor
        cur = conn.cursor()
        #query = " select useruuid, rauserid from UserStatus " \
        #        " where relationshipid = '" + relationship_did + "'  and statusid = '2'"
        # print(query)
        #cur.execute(str(query))

        cur.callproc("func_GetUUIDByRelationshipId",[relationship_did] )
        # print("The number of parts: ", cur.rowcount)
        user_data = cur.fetchmany()
        user_uuid_value = None
        requester_id_value = None
        for row in user_data:
            user_uuid_value = row[0]
            requester_id_value = row[1]
        # close the communication with the PostgreSQL
        cur.close()
        return user_uuid_value, requester_id_value
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()
            # print('Database connection closed.')


def check_userid_status(user_id, requester_id):
    conn = None
    try:
        # read connection parameters
        params = config.config()

        # connect to the PostgreSQL server
        conn = psycopg2.connect(**params)

        # create a cursor
        cur = conn.cursor()
        #query = " select US.qr_code_string,StatusCode From UserStatus as US left join StatusMaster on US.StatusId = StatusMaster.StatusID " \
        #        " where useruuid = '" + uuid + "'  and rauserid = '" + requester_id + "'"

        #print(query)
        cur.callproc("func_GetQrCodeWithStatus", [user_id,requester_id])
        # print("The number of parts: ", cur.rowcount)
        user_data = cur.fetchmany()
        qr_code = None,
        status_id = None
        for row in user_data:
            qr_code = row[0].strip()
            status_id = row[1]
        # close the communication with the PostgreSQL
        cur.close()
        return status_id, qr_code
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()
            # print('Database connection closed.')


def insert_user_status(user_uuid, relationship_did, qr_code, requester_id):
    is_inserted = 0
    try:
        # read connection parameters
        Created_User = config.Config.APPLICATION_ID
        params = config.config()
        conn = psycopg2.connect(**params)
        # create a cursor
        cur = conn.cursor()
        cur.execute('CALL proc_InsertUserStatus(%s,%s,%s,%s)', (user_uuid, relationship_did, qr_code, requester_id))
        conn.commit()
        # close the communication with the PostgreSQL
        cur.close()
        return is_inserted
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return is_inserted


def update_user_status(relationship_did, received_orders, status_id):
    is_updated = 0
    try:
        # read connection parameters
        params = config.config()
        conn = psycopg2.connect(**params)
        # create a cursor
        cur = conn.cursor()
        #current_date_time = datetime.utcnow().strftime('%Y-%m-%d-%H:%M:%S')
        cur.execute('CALL proc_updateuserstatus(%s,%s,%s)', (relationship_did, received_orders, status_id))
        conn.commit()
        # close the communication with the PostgreSQL
        cur.close()
        return is_updated
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return is_updated


def logger(log_type, application, request_type, user_uuid,method_name, message, status):
    is_inserted = 0
    try:
        # read connection parameters
        params = config.config()
        conn = psycopg2.connect(**params)
        # create a cursor
        cur = conn.cursor()
        #query = " insert into LoggData(LoggType,application,RequestType ,MethodName, MessageData,status,CreatedDate) " \
        #        " values ('" + log_type + "','" + application + "','" + request_type + "' ," \
        #        "'" + method_name + "','" + message + "','" + status + "', Now() )"
        #print(query)
        cur.execute('CALL proc_loggData(%s,%s,%s,%s,%s,%s,%s)', (log_type,application, request_type,user_uuid, method_name,message,status))

        #cur.execute(str(query))
        conn.commit()
        # close the communication with the PostgreSQL
        cur.close()
        return is_inserted
    except (Exception, psycopg2.DatabaseError) as error:
        return is_inserted




#qr_code_data = "Test Qr Code"
#print(insert_user_status(12345,"d3232234ewfsfsd",qr_code_data,123456))
#print(logger("Audit","URS","Inbound",12345,"Create Digital Credentials","MessageData","200"))
#print(check_userid_status(12345,123456))
#print(get_userid("d3232234ewfsfsd"))
#print(get_user_status_by_uuid(12345))
#print(update_user_status(12345,"d3232234ewfsfsd",3))
#print(check_userid_status(12345,123456))
#print(update_user_status('BUAGyv4H6PNvAzBbLefrgc',"abc123",2))
#print(update_user_status('',"abc123",3))

