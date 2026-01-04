# PostgreSQL MCP Server

A comprehensive PostgreSQL database management MCP server for Claude.ai integration. Provides **56 tools** for complete database administration, querying, monitoring, and maintenance.

## Features

- **56 Database Tools**: Complete PostgreSQL management capabilities
- **SSE Transport**: Server-Sent Events for real-time MCP communication
- **Connection Pooling**: Efficient database connections with pg Pool (max 20)
- **Parameterized Queries**: SQL injection prevention throughout
- **Railway Ready**: Configured for easy Railway deployment

## Tools (56 Total)

### Connection & Info (2)
| Tool | Description |
|------|-------------|
| `test_connection` | Test database connectivity |
| `get_database_info` | Get database statistics and version |

### Schema Management (7)
| Tool | Description |
|------|-------------|
| `list_schemas` | List all database schemas |
| `create_schema` | Create a new schema |
| `drop_schema` | Drop a schema |
| `list_tables` | List tables with sizes and column counts |
| `describe_table` | Get detailed table structure (columns, constraints, indexes) |
| `list_views` | List views with definitions |
| `list_functions` | List functions and procedures |

### Query Execution (3)
| Tool | Description |
|------|-------------|
| `execute_query` | Execute SELECT queries (read-only) |
| `execute_write` | Execute INSERT, UPDATE, DELETE, DDL statements |
| `execute_transaction` | Execute multiple statements in a transaction |

### Table Operations (6)
| Tool | Description |
|------|-------------|
| `create_table` | Create tables with full column definitions |
| `drop_table` | Drop tables (with CASCADE option) |
| `alter_table` | Add/drop/modify columns and constraints |
| `truncate_table` | Truncate tables |
| `copy_table` | Copy table structure and optionally data |
| `rename_table` | Rename a table |

### Index Management (3)
| Tool | Description |
|------|-------------|
| `create_index` | Create indexes (supports all PostgreSQL index types) |
| `drop_index` | Drop indexes |
| `list_indexes` | List indexes for a table |

### CRUD Operations (4)
| Tool | Description |
|------|-------------|
| `insert_row` | Insert data with RETURNING support |
| `update_rows` | Update rows with parameterized WHERE |
| `delete_rows` | Delete rows with parameterized WHERE |
| `select_rows` | Query with filtering, ordering, pagination |

### Performance Analysis (12)
| Tool | Description |
|------|-------------|
| `explain_query` | Get query execution plans |
| `get_table_stats` | Get table statistics |
| `get_active_connections` | View active database connections |
| `get_slow_queries` | Find long-running queries |
| `get_database_sizes` | Get sizes of all databases |
| `get_table_sizes` | Get sizes of all tables in a schema |
| `get_bloat` | Get table and index bloat estimates |
| `get_index_usage` | Get index usage statistics |
| `get_unused_indexes` | Find rarely used indexes |
| `get_cache_hit_ratio` | Get buffer cache hit ratio |
| `get_table_row_counts` | Get row counts for all tables |
| `get_column_stats` | Get column statistics for a table |

### Maintenance (3)
| Tool | Description |
|------|-------------|
| `vacuum_table` | Run VACUUM (regular or FULL) |
| `analyze_table` | Update table statistics for query planner |
| `reindex` | Rebuild indexes |

### Sequences (3)
| Tool | Description |
|------|-------------|
| `list_sequences` | List all sequences |
| `get_sequence_value` | Get current sequence value |
| `set_sequence_value` | Set sequence value |

### Extensions (3)
| Tool | Description |
|------|-------------|
| `list_extensions` | List installed extensions |
| `list_available_extensions` | List available extensions |
| `create_extension` | Install extensions |

### Users & Permissions (2)
| Tool | Description |
|------|-------------|
| `list_roles` | List database roles/users |
| `get_table_permissions` | View table permissions |

### Relationships & Dependencies (4)
| Tool | Description |
|------|-------------|
| `list_foreign_keys` | List all foreign key relationships |
| `list_triggers` | List all triggers in a schema |
| `get_constraints` | Get all constraints for a table |
| `get_dependent_objects` | Get objects dependent on a table |

### Monitoring & Admin (4)
| Tool | Description |
|------|-------------|
| `get_locks` | Get current database locks |
| `kill_connection` | Terminate a database connection |
| `search_columns` | Search for columns by name across all tables |
| `get_pg_settings` | Get PostgreSQL configuration settings |

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
3. Add environment variables:
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
- Parameterized queries are supported throughout to prevent SQL injection
- Consider using read-only database credentials for safety
- `kill_connection` uses pg_cancel_backend by default (graceful), set `force: true` for pg_terminate_backend

## License

MIT
