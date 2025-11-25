#!/usr/bin/env python3

import mysql.connector
import os
import sys
from datetime import datetime
import time

def test_connection(host, port, user, password, connection_name, conn_attrs):
    """Test connection with custom attributes"""
    
    print(f"\n{'='*60}")
    print(f"Testing: {connection_name}")
    print(f"Host: {host}:{port}")
    print(f"User: {user}")
    print(f"{'='*60}\n")
    
    try:
        # Connect with custom connection attributes
        conn = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            conn_attrs=conn_attrs,
            database="test",
            ssl_ca = "/certs/ca.pem",
            ssl_cert = "/certs/client-cert.pem",
            ssl_key = "/certs/client-key.pem",
            ssl_verify_cert = True,
            ssl_verify_identity = True,
            use_pure  = True
        )
        
        cursor = conn.cursor()
        
        # Get connection ID
        cursor.execute("SELECT CONNECTION_ID()")
        conn_id = cursor.fetchone()[0]
        print(f"✓ Connected successfully! Connection ID: {conn_id}\n")
        
        # Test a simple query
        print("\n--- Test Query ---")
        cursor.execute("SELECT DATABASE(), USER(), VERSION()")
        db, user, version = cursor.fetchone()
        print(f"  Database: {db}")
        print(f"  User: {user}")
        print(f"  Version: {version}")

        for i in range(10):
            cursor.execute("SELECT * from users")
            users = cursor.fetchall()
            
            cursor.execute("SELECT * from posts") 
            posts = cursor.fetchall()
            
            print(f"Iteration {i+1}: Found {len(users)} users, {len(posts)} posts")
            time.sleep(60)

        print("Loop completed!")
        
        cursor.close()
        conn.close()
        
        print(f"\n✓ Test completed successfully for {connection_name}\n")
        return True
        
    except mysql.connector.Error as err:
        print(f"✗ Connection failed: {err}\n")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}\n")
        return False

def main():
    """Main test function"""
    
    print("\n" + "="*60)
    print("MySQL Connection Attributes Test")
    print("="*60)
    
    # Test : Connection through proxy
    print("\n[Test] Connection through warden proxy")
    test_connection(
        host=os.getenv('PROXY_HOST', 'warden'),
        port=int(os.getenv('PROXY_PORT', '4000')),
        user=os.getenv('PROXY_USER', 'test_user@ondemand_role'),
        password=os.getenv('PROXY_PASSWORD', ''),
        connection_name='warden-connection',
        conn_attrs={
            'token': 'token',
        }
    )
    
    print("\n" + "="*60)
    print("All tests completed!")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()