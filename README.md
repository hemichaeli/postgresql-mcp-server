# PostgreSQL MCP Server

A comprehensive PostgreSQL database management MCP server for Claude.ai integration. Provides 40+ tools for complete database administration, querying, and maintenance.

## Features

### Connection & Information
- `test_connection` - Test database connectivity
- `get_database_info` - Get database statistics and version

### Schema Management
- `list_schemas` - List all database schemas
- `list_tables` - List tables with sizes and column counts
- `describe_table` - Get detailed table structure (columns, constraints, indexes)
- `list_views` - List views with definitions
- `list_functions` - List functions and procedures

### Query Execution
- `execute_query` - Execute SELECT queries (read-only)
- `execute_write` - Execute INSERT, UPDATE, DELETE, DDL statements
- `execute_transaction` - Execute multiple statements in a transaction

### Table Operations
- `create_table` - Create tables with full column definitions
- `drop_table` - Drop tables (with CASCADE option)
- `alter_table` - Add/drop/modify columns and constraints
- `truncate_table` - Truncate tables

### Index Management
- `create_index` - Create indexes (supports all PostgreSQL index types)
- `drop_index` - Drop indexes
- `list_indexes` - List indexes for a table

### CRUD Operations
- `insert_row` - Insert data with RETURNING support
- `update_rows` - Update rows with parameterized WHERE
- `delete_rows` - Delete rows with parameterized WHERE
- `select_rows` - Query with filtering, ordering, pagination

### Performance Analysis
- `explain_query` - Get query execution plans
- `get_table_stats` - Get table statistics
- `get_active_connections` - View active database connections
- `get_slow_queries` - Find long-running queries

### Maintenance
- `vacuum_table` - Run VACUUM (regular or FULL)
- `reindex` - Rebuild indexes

### Sequences
- `list_sequences` - List all sequences
- `get_sequence_value` - Get current sequence value
- `set_sequence_value` - Set sequence value

### Extensions
- `list_extensions` - List installed extensions
- `list_available_extensions` - List available extensions
- `create_extension` - Install extensions

### Users & Permissions
- `list_roles` - List database roles/users
- `get_table_permissions` - View table permissions

## Deployment

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `DATABASE_SSL` | No | Set to "true" to enable SSL |
| `PORT` | No | Server port (default: 3000) |

### Railway Deployment

1. Create a new Railway project
2. Connect your GitHub repository
3. Add the following environment variables:
   - `DATABASE_URL` - Your PostgreSQL connection string
   - `DATABASE_SSL` - "true" if using SSL

### Connection String Format

```
postgresql://username:password@host:port/database
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Server info and tool list |
| `/sse` | GET | SSE connection for MCP |
| `/messages` | POST | MCP message handler |
| `/health` | GET | Health check with DB status |

## Usage with Claude.ai

Add as an MCP connector in Claude.ai settings:

**URL:** `https://your-railway-url.up.railway.app/sse`

## Security Considerations

- The `execute_query` tool only allows SELECT/WITH queries
- Use `execute_write` for modifications (INSERT/UPDATE/DELETE/DDL)
- Parameterized queries are supported to prevent SQL injection
- Consider using read-only database credentials for safety

## License

MIT
