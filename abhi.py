#!/usr/bin/env python3
"""
Data-Only PostgreSQL Export Script
Exports only INSERT statements (no schema/structure)
Perfect for importing data into existing tables
"""

import os
import sys
import datetime
from decimal import Decimal
import json

# Database configuration
CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'username': 'postgres',
    'password': '1234',
    'database': 'saas_platform'
}

def install_psycopg2():
    """Install psycopg2 if not available"""
    try:
        import psycopg2
        return True
    except ImportError:
        print("📦 Installing psycopg2-binary...")
        try:
            import subprocess
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'psycopg2-binary'])
            print("✅ psycopg2-binary installed successfully!")
            import psycopg2
            return True
        except Exception as e:
            print(f"❌ Failed to install psycopg2: {e}")
            print("📋 Please install manually: pip install psycopg2-binary")
            return False

def connect_database():
    """Connect to PostgreSQL database"""
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        conn_str = (f"host={CONFIG['host']} port={CONFIG['port']} "
                   f"dbname={CONFIG['database']} user={CONFIG['username']} "
                   f"password={CONFIG['password']}")
        
        conn = psycopg2.connect(conn_str, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return None

def get_tables_info(conn):
    """Get list of tables and their row counts"""
    try:
        with conn.cursor() as cur:
            # Get all tables in public schema
            cur.execute("""
                SELECT tablename 
                FROM pg_tables 
                WHERE schemaname = 'public'
                ORDER BY tablename
            """)
            tables = [row['tablename'] for row in cur.fetchall()]
            
            # Get row counts for each table
            table_info = {}
            total_rows = 0
            
            for table in tables:
                cur.execute(f"SELECT COUNT(*) as count FROM {table}")
                row_count = cur.fetchone()['count']
                table_info[table] = row_count
                total_rows += row_count
            
            return tables, table_info, total_rows
            
    except Exception as e:
        print(f"❌ Error getting table info: {e}")
        return [], {}, 0

def format_value_for_sql(value):
    """Format a Python value for SQL INSERT statement"""
    if value is None:
        return 'NULL'
    elif isinstance(value, bool):
        return 'TRUE' if value else 'FALSE'
    elif isinstance(value, (int, float, Decimal)):
        return str(value)
    elif isinstance(value, str):
        # Escape single quotes and backslashes
        escaped = value.replace("\\", "\\\\").replace("'", "''")
        return f"'{escaped}'"
    elif isinstance(value, (list, dict)):
        # Handle JSON/JSONB columns
        json_str = json.dumps(value).replace("'", "''")
        return f"'{json_str}'"
    elif hasattr(value, 'isoformat'):
        # Handle datetime objects
        return f"'{value.isoformat()}'"
    else:
        # Handle other types by converting to string
        str_value = str(value).replace("'", "''")
        return f"'{str_value}'"

def export_table_data(conn, table_name, batch_size=1000, use_copy_format=False):
    """Export data from a single table"""
    try:
        with conn.cursor() as cur:
            # Get column names
            cur.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = %s
                ORDER BY ordinal_position
            """, (table_name,))
            
            columns = [row['column_name'] for row in cur.fetchall()]
            
            if not columns:
                return f"-- No columns found for table {table_name}\n"
            
            # Get total row count
            cur.execute(f"SELECT COUNT(*) as count FROM {table_name}")
            total_rows = cur.fetchone()['count']
            
            if total_rows == 0:
                return f"-- No data in table {table_name}\n\n"
            
            print(f"   📄 Exporting {total_rows:,} rows from {table_name}...")
            
            # Build column list for INSERT
            column_list = ", ".join(columns)
            
            # Export data in batches
            sql_statements = []
            sql_statements.append(f"-- Data for table: {table_name} ({total_rows:,} rows)")
            
            if use_copy_format:
                # Use COPY format (faster for large datasets)
                sql_statements.append(f"COPY {table_name} ({column_list}) FROM stdin;")
            
            exported_rows = 0
            
            for offset in range(0, total_rows, batch_size):
                cur.execute(f"SELECT * FROM {table_name} ORDER BY 1 LIMIT %s OFFSET %s", 
                           (batch_size, offset))
                
                rows = cur.fetchall()
                
                if use_copy_format:
                    # COPY format - tab-separated values
                    for row in rows:
                        values = []
                        for col in columns:
                            value = row[col]
                            if value is None:
                                values.append('\\N')
                            else:
                                # Escape tabs, newlines, backslashes
                                str_val = str(value).replace('\\', '\\\\').replace('\t', '\\t').replace('\n', '\\n').replace('\r', '\\r')
                                values.append(str_val)
                        sql_statements.append('\t'.join(values))
                else:
                    # INSERT format
                    for row in rows:
                        values = []
                        for col in columns:
                            values.append(format_value_for_sql(row[col]))
                        
                        values_str = ", ".join(values)
                        sql_statements.append(f"INSERT INTO {table_name} ({column_list}) VALUES ({values_str});")
                
                exported_rows += len(rows)
                
                # Show progress for large tables
                if total_rows > 5000 and exported_rows % 5000 == 0:
                    progress = (exported_rows / total_rows) * 100
                    print(f"     Progress: {exported_rows:,}/{total_rows:,} ({progress:.1f}%)")
            
            if use_copy_format:
                sql_statements.append("\\.")
            
            sql_statements.append("")  # Empty line after table
            
            return "\n".join(sql_statements) + "\n"
            
    except Exception as e:
        print(f"❌ Error exporting data from {table_name}: {e}")
        return f"-- Error exporting data from {table_name}: {e}\n\n"

def export_data_only(include_tables=None, exclude_tables=None, use_copy_format=False):
    """Export only data from all tables"""
    
    print("📊 Data-Only PostgreSQL Export Tool")
    print("=" * 60)
    print(f"📋 Database: {CONFIG['database']}")
    print(f"🎯 Export Type: DATA ONLY (no schema)")
    print(f"🔧 Format: {'COPY' if use_copy_format else 'INSERT'} statements")
    print("=" * 60)
    
    # Install psycopg2 if needed
    if not install_psycopg2():
        return None
    
    # Connect to database
    print("🔌 Connecting to database...")
    conn = connect_database()
    if not conn:
        return None
    
    try:
        # Get table information
        print("📊 Analyzing tables...")
        tables, table_info, total_rows = get_tables_info(conn)
        
        if not tables:
            print("❌ No tables found!")
            return None
        
        # Filter tables if specified
        if include_tables:
            tables = [t for t in tables if t in include_tables]
            print(f"🎯 Including only: {', '.join(tables)}")
        
        if exclude_tables:
            tables = [t for t in tables if t not in exclude_tables]
            print(f"🚫 Excluding: {', '.join(exclude_tables)}")
        
        print(f"📋 Found {len(tables)} tables with {total_rows:,} total rows:")
        
        # Show table info
        for table in tables:
            print(f"     • {table}: {table_info[table]:,} rows")
        
        # Create output file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        format_suffix = "copy" if use_copy_format else "insert"
        output_file = f"saas_platform_data_only_{format_suffix}_{timestamp}.sql"
        
        print(f"\n🚀 Starting data export to: {output_file}")
        
        # Export data
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write(f"-- PostgreSQL Data-Only Export\n")
            f.write(f"-- Database: {CONFIG['database']}\n")
            f.write(f"-- Exported: {datetime.datetime.now()}\n")
            f.write(f"-- Format: {'COPY' if use_copy_format else 'INSERT'} statements\n")
            f.write(f"-- Tables: {len(tables)}\n")
            f.write(f"-- Total Rows: {total_rows:,}\n")
            f.write(f"--\n")
            f.write(f"-- NOTE: This file contains DATA ONLY\n")
            f.write(f"-- Make sure target database has the correct table structure\n")
            f.write(f"--\n\n")
            
            # Disable triggers and constraints for faster import
            if not use_copy_format:
                f.write("-- Disable triggers for faster import\n")
                f.write("SET session_replication_role = replica;\n\n")
            
            # Export each table
            for i, table_name in enumerate(tables, 1):
                print(f"📋 Processing table {i}/{len(tables)}: {table_name}")
                
                if table_info[table_name] == 0:
                    print(f"     ⚠️  Table {table_name} is empty, skipping...")
                    f.write(f"-- Table {table_name} is empty\n\n")
                    continue
                
                # Clear table before inserting (optional)
                if not use_copy_format:
                    f.write(f"-- Clear existing data from {table_name}\n")
                    f.write(f"DELETE FROM {table_name};\n\n")
                
                # Export table data
                data_sql = export_table_data(conn, table_name, batch_size=1000, use_copy_format=use_copy_format)
                f.write(data_sql)
            
            # Re-enable triggers
            if not use_copy_format:
                f.write("\n-- Re-enable triggers\n")
                f.write("SET session_replication_role = DEFAULT;\n")
        
        # Get file size
        file_size = os.path.getsize(output_file)
        file_size_mb = file_size / (1024 * 1024)
        
        print(f"\n✅ Data export completed successfully!")
        print(f"📁 File: {output_file}")
        print(f"📏 Size: {file_size_mb:.2f} MB ({file_size:,} bytes)")
        
        # Handle large files
        if file_size_mb > 5:
            print(f"⚠️  File is larger than 5MB")
            choice = input("🔪 Split file for easier phpPgAdmin import? (y/n): ")
            if choice.lower() == 'y':
                split_files = split_data_file(output_file, 5)
                create_data_import_instructions(split_files, use_copy_format)
                return split_files
        
        create_data_import_instructions([output_file], use_copy_format)
        return [output_file]
        
    except Exception as e:
        print(f"❌ Export failed: {e}")
        return None
    finally:
        conn.close()

def split_data_file(filename, max_size_mb):
    """Split large data file into chunks"""
    print(f"🔪 Splitting {filename} into {max_size_mb}MB chunks...")
    
    max_size_bytes = max_size_mb * 1024 * 1024
    base_name = filename.replace('.sql', '')
    
    split_files = []
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            current_file_num = 1
            current_size = 0
            current_content = []
            
            # Keep header for each file
            header_lines = []
            in_header = True
            
            for line in f:
                # Collect header lines
                if in_header and (line.startswith('--') or line.strip() == ''):
                    header_lines.append(line)
                    continue
                elif in_header:
                    in_header = False
                    # Add the SET statement if present
                    if 'SET session_replication_role' in line:
                        header_lines.append(line)
                        continue
                
                line_size = len(line.encode('utf-8'))
                
                # Check if we need to start a new file
                if current_size + line_size > max_size_bytes and current_content:
                    # Save current chunk
                    chunk_filename = f"{base_name}_part_{current_file_num:02d}.sql"
                    
                    with open(chunk_filename, 'w', encoding='utf-8') as chunk_file:
                        # Write header
                        chunk_file.writelines(header_lines)
                        chunk_file.write(f"-- Part {current_file_num}\n\n")
                        # Write content
                        chunk_file.writelines(current_content)
                        # Add footer if needed
                        if any('SET session_replication_role = replica' in h for h in header_lines):
                            chunk_file.write("\n-- Re-enable triggers\n")
                            chunk_file.write("SET session_replication_role = DEFAULT;\n")
                    
                    split_files.append(chunk_filename)
                    print(f"   ✅ Created: {chunk_filename}")
                    
                    # Start new chunk
                    current_file_num += 1
                    current_content = [line]
                    current_size = line_size
                else:
                    current_content.append(line)
                    current_size += line_size
            
            # Save last chunk
            if current_content:
                chunk_filename = f"{base_name}_part_{current_file_num:02d}.sql"
                
                with open(chunk_filename, 'w', encoding='utf-8') as chunk_file:
                    chunk_file.writelines(header_lines)
                    chunk_file.write(f"-- Part {current_file_num} (Final)\n\n")
                    chunk_file.writelines(current_content)
                    if any('SET session_replication_role = replica' in h for h in header_lines):
                        chunk_file.write("\n-- Re-enable triggers\n")
                        chunk_file.write("SET session_replication_role = DEFAULT;\n")
                
                split_files.append(chunk_filename)
                print(f"   ✅ Created: {chunk_filename}")
        
        # Remove original large file
        os.remove(filename)
        print(f"🗑️  Removed original large file: {filename}")
        
        return split_files
        
    except Exception as e:
        print(f"❌ Error splitting file: {e}")
        return [filename]

def create_data_import_instructions(files, use_copy_format):
    """Create import instructions for data-only files"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    instructions_file = f"DATA_IMPORT_INSTRUCTIONS_{timestamp}.txt"
    
    format_name = "COPY" if use_copy_format else "INSERT"
    
    instructions = f"""
📊 Data-Only Import Instructions for phpPgAdmin
===============================================

Database: {CONFIG['database']}
Export Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Format: {format_name} statements
Files to Import: {len(files)}

⚠️  IMPORTANT: DATA-ONLY IMPORT
===============================================
This export contains ONLY data (INSERT/COPY statements).
The target database MUST already have the correct table structure!

If you need the schema:
1. Export schema separately, or
2. Create tables manually before importing this data

📋 STEP-BY-STEP IMPORT PROCESS:
===============================================

1. ✅ VERIFY TARGET DATABASE HAS TABLES
   - Make sure {CONFIG['database']} database exists
   - Verify all tables exist with correct structure
   - Check column names and data types match

2. 📁 PREPARE FILES
   Files to import in order:
"""
    
    for i, file in enumerate(files, 1):
        size_mb = os.path.getsize(file) / (1024 * 1024)
        instructions += f"   {i}. {file} ({size_mb:.2f} MB)\n"
    
    instructions += f"""
3. 🌐 ACCESS PHPPGADMIN
   - Login to cPanel → phpPgAdmin
   - Connect to PostgreSQL server
   - Select database: {CONFIG['database']}

4. 📥 IMPORT DATA FILES
"""
    
    if len(files) == 1:
        instructions += f"""
   SINGLE FILE IMPORT:
   - Click "SQL" tab
   - Open {files[0]} in text editor
   - Copy ALL content and paste into SQL box
   - Click "Execute"
   - Wait for completion
"""
    else:
        instructions += f"""
   MULTIPLE FILES - IMPORT IN EXACT ORDER:
"""
        for i, file in enumerate(files, 1):
            instructions += f"""
   Step {i}: Import {file}
   - Click "SQL" tab
   - Open {file} in text editor
   - Copy ALL content and paste
   - Click "Execute"
   - Wait for completion before next file
"""
    
    if use_copy_format:
        instructions += f"""
⚠️  COPY FORMAT NOTES:
===============================================
- Files use PostgreSQL COPY format
- May not work in all phpPgAdmin versions
- If COPY fails, re-export using INSERT format:
  python script.py --format insert
"""
    
    instructions += f"""
5. ✅ VERIFY DATA IMPORT
   - Check row counts in each table
   - Spot-check data integrity
   - Test your application

🔧 ALTERNATIVE IMPORT METHODS:
===============================================

💻 Command Line (if available):
   psql -h localhost -U username -d {CONFIG['database']} < filename.sql

🌐 pgAdmin:
   - Use Query Tool
   - Copy/paste file contents
   - Execute SQL

📊 DATA VERIFICATION:
===============================================
After import, verify row counts match:
"""
    
    # Connect and get row counts for verification
    try:
        if install_psycopg2():
            conn = connect_database()
            if conn:
                tables, table_info, total_rows = get_tables_info(conn)
                for table in sorted(tables):
                    instructions += f"   {table}: {table_info[table]:,} rows\n"
                conn.close()
    except:
        instructions += "   (Connect to database to see expected row counts)\n"
    
    instructions += f"""
🚨 TROUBLESHOOTING:
===============================================

❌ "Table does not exist" errors:
   - You're importing data-only export
   - Create tables first or import schema

❌ "Column does not exist" errors:
   - Table structure doesn't match
   - Check column names and types

❌ Data type errors:
   - Source and target schemas differ
   - Verify table definitions match

❌ Constraint violations:
   - Foreign key constraints may fail
   - Consider disabling constraints during import

💡 BEST PRACTICES:
===============================================
   - Backup target database before import
   - Import during low-traffic hours  
   - Monitor database space during import
   - Keep original export files as backup

Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Tool: Data-Only PostgreSQL Exporter
"""
    
    with open(instructions_file, 'w', encoding='utf-8') as f:
        f.write(instructions)
    
    print(f"📝 Instructions created: {instructions_file}")
    return instructions_file

def main():
    """Main execution with options"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Export PostgreSQL data only')
    parser.add_argument('--format', choices=['insert', 'copy'], default='insert',
                       help='Export format (default: insert)')
    parser.add_argument('--include', nargs='+', help='Include only these tables')
    parser.add_argument('--exclude', nargs='+', help='Exclude these tables')
    parser.add_argument('--list-tables', action='store_true', help='List tables and exit')
    
    args = parser.parse_args()
    
    # List tables option
    if args.list_tables:
        if install_psycopg2():
            conn = connect_database()
            if conn:
                tables, table_info, total_rows = get_tables_info(conn)
                print(f"\n📋 Tables in {CONFIG['database']}:")
                print("=" * 40)
                for table in sorted(tables):
                    print(f"  {table:<25} {table_info[table]:,} rows")
                print("=" * 40)
                print(f"Total: {len(tables)} tables, {total_rows:,} rows")
                conn.close()
        return
    
    # Export data
    use_copy = (args.format == 'copy')
    files = export_data_only(
        include_tables=args.include,
        exclude_tables=args.exclude, 
        use_copy_format=use_copy
    )
    
    if files:
        print("\n🎉 DATA EXPORT COMPLETED!")
        print("\n📦 Files ready for import:")
        
        total_size = 0
        for file in files:
            size_mb = os.path.getsize(file) / (1024 * 1024)
            total_size += size_mb
            print(f"   📁 {file} ({size_mb:.2f} MB)")
        
        print(f"\n📏 Total size: {total_size:.2f} MB")
        print(f"📝 Check DATA_IMPORT_INSTRUCTIONS file!")
        print(f"⚠️  Remember: Target database must have table structure!")

if __name__ == "__main__":
    # Quick run without arguments
    if len(sys.argv) == 1:
        files = export_data_only(use_copy_format=False)
        
        if files:
            print("\n🎉 DATA EXPORT COMPLETED!")
            total_size = sum(os.path.getsize(f) for f in files) / (1024 * 1024)
            print(f"📦 {len(files)} files created ({total_size:.2f} MB total)")
    else:
        main()