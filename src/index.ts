import express, { Request, Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { Pool, PoolClient, QueryResult } from "pg";
import { randomUUID } from "crypto";
import { z } from "zod";

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL connection configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : undefined,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// Store transports by session ID
const transports: Record<string, SSEServerTransport> = {};

// Helper function to execute queries safely
async function executeQuery(query: string, params?: any[]): Promise<QueryResult> {
  const client = await pool.connect();
  try {
    return await client.query(query, params);
  } finally {
    client.release();
  }
}

// Helper to format query results
function formatResults(result: QueryResult): string {
  return JSON.stringify({
    rows: result.rows,
    rowCount: result.rowCount,
    fields: result.fields?.map(f => ({ name: f.name, dataType: f.dataTypeID }))
  }, null, 2);
}

// Create and configure MCP server
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "postgresql-mcp-server",
    version: "1.0.0",
  });

  // ============ CONNECTION & INFO TOOLS ============

  server.tool("test_connection", "Test database connection", {}, async () => {
    try {
      const result = await executeQuery("SELECT NOW() as current_time, current_database() as database, current_user as user, version() as version");
      return { content: [{ type: "text", text: JSON.stringify({ success: true, ...result.rows[0] }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ success: false, error: error.message }, null, 2) }] };
    }
  });

  server.tool("get_database_info", "Get database information and statistics", {}, async () => {
    try {
      const dbInfo = await executeQuery(`
        SELECT 
          current_database() as database_name,
          current_user as current_user,
          pg_size_pretty(pg_database_size(current_database())) as database_size,
          (SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public') as table_count,
          (SELECT count(*) FROM information_schema.views WHERE table_schema = 'public') as view_count,
          version() as pg_version
      `);
      return { content: [{ type: "text", text: JSON.stringify(dbInfo.rows[0], null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  // ============ SCHEMA TOOLS ============

  server.tool("list_schemas", "List all schemas in the database", {}, async () => {
    const result = await executeQuery(`
      SELECT schema_name, schema_owner 
      FROM information_schema.schemata 
      WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
      ORDER BY schema_name
    `);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  server.tool("list_tables", "List all tables in a schema", {
    schema: z.string().optional().describe("Schema name (default: public)")
  }, async ({ schema = "public" }) => {
    const result = await executeQuery(`
      SELECT 
        t.table_name,
        t.table_type,
        pg_size_pretty(pg_total_relation_size(quote_ident(t.table_schema) || '.' || quote_ident(t.table_name))) as total_size,
        (SELECT count(*) FROM information_schema.columns c WHERE c.table_name = t.table_name AND c.table_schema = t.table_schema) as column_count
      FROM information_schema.tables t
      WHERE t.table_schema = $1
      ORDER BY t.table_name
    `, [schema]);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  server.tool("describe_table", "Get detailed table structure", {
    table: z.string().describe("Table name"),
    schema: z.string().optional().describe("Schema name (default: public)")
  }, async ({ table, schema = "public" }) => {
    // Get columns
    const columns = await executeQuery(`
      SELECT 
        c.column_name,
        c.data_type,
        c.character_maximum_length,
        c.numeric_precision,
        c.is_nullable,
        c.column_default,
        c.ordinal_position
      FROM information_schema.columns c
      WHERE c.table_schema = $1 AND c.table_name = $2
      ORDER BY c.ordinal_position
    `, [schema, table]);

    // Get constraints
    const constraints = await executeQuery(`
      SELECT 
        tc.constraint_name,
        tc.constraint_type,
        kcu.column_name,
        ccu.table_name AS foreign_table_name,
        ccu.column_name AS foreign_column_name
      FROM information_schema.table_constraints tc
      LEFT JOIN information_schema.key_column_usage kcu 
        ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
      LEFT JOIN information_schema.constraint_column_usage ccu 
        ON ccu.constraint_name = tc.constraint_name AND ccu.table_schema = tc.table_schema
      WHERE tc.table_schema = $1 AND tc.table_name = $2
    `, [schema, table]);

    // Get indexes
    const indexes = await executeQuery(`
      SELECT 
        indexname,
        indexdef
      FROM pg_indexes
      WHERE schemaname = $1 AND tablename = $2
    `, [schema, table]);

    return { content: [{ type: "text", text: JSON.stringify({ columns: columns.rows, constraints: constraints.rows, indexes: indexes.rows }, null, 2) }] };
  });

  server.tool("list_views", "List all views in a schema", {
    schema: z.string().optional().describe("Schema name (default: public)")
  }, async ({ schema = "public" }) => {
    const result = await executeQuery(`
      SELECT table_name as view_name, view_definition
      FROM information_schema.views
      WHERE table_schema = $1
      ORDER BY table_name
    `, [schema]);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  server.tool("list_functions", "List all functions in a schema", {
    schema: z.string().optional().describe("Schema name (default: public)")
  }, async ({ schema = "public" }) => {
    const result = await executeQuery(`
      SELECT 
        p.proname as function_name,
        pg_get_function_arguments(p.oid) as arguments,
        pg_get_function_result(p.oid) as return_type,
        CASE p.prokind
          WHEN 'f' THEN 'function'
          WHEN 'p' THEN 'procedure'
          WHEN 'a' THEN 'aggregate'
          WHEN 'w' THEN 'window'
        END as kind
      FROM pg_proc p
      JOIN pg_namespace n ON p.pronamespace = n.oid
      WHERE n.nspname = $1
      ORDER BY p.proname
    `, [schema]);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  // ============ QUERY TOOLS ============

  server.tool("execute_query", "Execute a SELECT query (read-only)", {
    query: z.string().describe("SQL SELECT query"),
    params: z.array(z.any()).optional().describe("Query parameters for prepared statement")
  }, async ({ query, params }) => {
    // Safety check - only allow SELECT queries
    const trimmedQuery = query.trim().toUpperCase();
    if (!trimmedQuery.startsWith("SELECT") && !trimmedQuery.startsWith("WITH")) {
      return { content: [{ type: "text", text: JSON.stringify({ error: "Only SELECT and WITH queries are allowed. Use execute_write for modifications." }, null, 2) }] };
    }
    try {
      const result = await executeQuery(query, params);
      return { content: [{ type: "text", text: formatResults(result) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  server.tool("execute_write", "Execute INSERT, UPDATE, DELETE, or DDL statement", {
    query: z.string().describe("SQL statement"),
    params: z.array(z.any()).optional().describe("Query parameters for prepared statement")
  }, async ({ query, params }) => {
    try {
      const result = await executeQuery(query, params);
      return { content: [{ type: "text", text: JSON.stringify({ 
        success: true, 
        rowCount: result.rowCount,
        command: result.command,
        rows: result.rows // For RETURNING clauses
      }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  server.tool("execute_transaction", "Execute multiple statements in a transaction", {
    statements: z.array(z.object({
      query: z.string(),
      params: z.array(z.any()).optional()
    })).describe("Array of SQL statements to execute in order")
  }, async ({ statements }) => {
    const client = await pool.connect();
    const results: any[] = [];
    
    try {
      await client.query("BEGIN");
      
      for (let i = 0; i < statements.length; i++) {
        const { query, params } = statements[i];
        const result = await client.query(query, params);
        results.push({
          index: i,
          command: result.command,
          rowCount: result.rowCount,
          rows: result.rows
        });
      }
      
      await client.query("COMMIT");
      return { content: [{ type: "text", text: JSON.stringify({ success: true, results }, null, 2) }] };
    } catch (error: any) {
      await client.query("ROLLBACK");
      return { content: [{ type: "text", text: JSON.stringify({ success: false, error: error.message, results }, null, 2) }] };
    } finally {
      client.release();
    }
  });

  // ============ TABLE OPERATIONS ============

  server.tool("create_table", "Create a new table", {
    table: z.string().describe("Table name"),
    columns: z.array(z.object({
      name: z.string(),
      type: z.string(),
      nullable: z.boolean().optional(),
      default: z.string().optional(),
      primaryKey: z.boolean().optional(),
      unique: z.boolean().optional(),
      references: z.object({
        table: z.string(),
        column: z.string()
      }).optional()
    })).describe("Column definitions"),
    schema: z.string().optional().describe("Schema name (default: public)")
  }, async ({ table, columns, schema = "public" }) => {
    const columnDefs = columns.map(col => {
      let def = `"${col.name}" ${col.type}`;
      if (col.primaryKey) def += " PRIMARY KEY";
      if (col.unique && !col.primaryKey) def += " UNIQUE";
      if (col.nullable === false) def += " NOT NULL";
      if (col.default) def += ` DEFAULT ${col.default}`;
      if (col.references) def += ` REFERENCES "${col.references.table}"("${col.references.column}")`;
      return def;
    });

    const query = `CREATE TABLE "${schema}"."${table}" (${columnDefs.join(", ")})`;
    
    try {
      await executeQuery(query);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, message: `Table ${schema}.${table} created`, query }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message, query }, null, 2) }] };
    }
  });

  server.tool("drop_table", "Drop a table", {
    table: z.string().describe("Table name"),
    schema: z.string().optional().describe("Schema name (default: public)"),
    cascade: z.boolean().optional().describe("Drop dependent objects")
  }, async ({ table, schema = "public", cascade = false }) => {
    const query = `DROP TABLE "${schema}"."${table}"${cascade ? " CASCADE" : ""}`;
    try {
      await executeQuery(query);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, message: `Table ${schema}.${table} dropped` }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  server.tool("alter_table", "Alter a table (add/drop/modify columns)", {
    table: z.string().describe("Table name"),
    schema: z.string().optional().describe("Schema name (default: public)"),
    action: z.enum(["ADD COLUMN", "DROP COLUMN", "ALTER COLUMN", "RENAME COLUMN", "ADD CONSTRAINT", "DROP CONSTRAINT"]),
    columnName: z.string().optional(),
    newColumnName: z.string().optional().describe("For RENAME COLUMN"),
    columnType: z.string().optional().describe("For ADD/ALTER COLUMN"),
    nullable: z.boolean().optional(),
    default: z.string().optional(),
    constraintName: z.string().optional(),
    constraintDefinition: z.string().optional()
  }, async ({ table, schema = "public", action, columnName, newColumnName, columnType, nullable, default: defaultVal, constraintName, constraintDefinition }) => {
    let query = `ALTER TABLE "${schema}"."${table}" `;
    
    switch (action) {
      case "ADD COLUMN":
        query += `ADD COLUMN "${columnName}" ${columnType}`;
        if (nullable === false) query += " NOT NULL";
        if (defaultVal) query += ` DEFAULT ${defaultVal}`;
        break;
      case "DROP COLUMN":
        query += `DROP COLUMN "${columnName}"`;
        break;
      case "ALTER COLUMN":
        if (columnType) query += `ALTER COLUMN "${columnName}" TYPE ${columnType}`;
        else if (nullable !== undefined) query += `ALTER COLUMN "${columnName}" ${nullable ? "DROP NOT NULL" : "SET NOT NULL"}`;
        else if (defaultVal) query += `ALTER COLUMN "${columnName}" SET DEFAULT ${defaultVal}`;
        break;
      case "RENAME COLUMN":
        query += `RENAME COLUMN "${columnName}" TO "${newColumnName}"`;
        break;
      case "ADD CONSTRAINT":
        query += `ADD CONSTRAINT "${constraintName}" ${constraintDefinition}`;
        break;
      case "DROP CONSTRAINT":
        query += `DROP CONSTRAINT "${constraintName}"`;
        break;
    }

    try {
      await executeQuery(query);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, query }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message, query }, null, 2) }] };
    }
  });

  server.tool("truncate_table", "Truncate a table (delete all rows)", {
    table: z.string().describe("Table name"),
    schema: z.string().optional().describe("Schema name (default: public)"),
    cascade: z.boolean().optional(),
    restartIdentity: z.boolean().optional().describe("Reset auto-increment sequences")
  }, async ({ table, schema = "public", cascade = false, restartIdentity = false }) => {
    let query = `TRUNCATE TABLE "${schema}"."${table}"`;
    if (restartIdentity) query += " RESTART IDENTITY";
    if (cascade) query += " CASCADE";
    
    try {
      await executeQuery(query);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, message: `Table ${schema}.${table} truncated` }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  // ============ INDEX TOOLS ============

  server.tool("create_index", "Create an index", {
    name: z.string().describe("Index name"),
    table: z.string().describe("Table name"),
    columns: z.array(z.string()).describe("Column names"),
    schema: z.string().optional(),
    unique: z.boolean().optional(),
    method: z.enum(["btree", "hash", "gist", "gin", "spgist", "brin"]).optional(),
    where: z.string().optional().describe("Partial index condition")
  }, async ({ name, table, columns, schema = "public", unique = false, method = "btree", where }) => {
    let query = `CREATE ${unique ? "UNIQUE " : ""}INDEX "${name}" ON "${schema}"."${table}" USING ${method} (${columns.map(c => `"${c}"`).join(", ")})`;
    if (where) query += ` WHERE ${where}`;
    
    try {
      await executeQuery(query);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, message: `Index ${name} created`, query }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message, query }, null, 2) }] };
    }
  });

  server.tool("drop_index", "Drop an index", {
    name: z.string().describe("Index name"),
    schema: z.string().optional()
  }, async ({ name, schema = "public" }) => {
    try {
      await executeQuery(`DROP INDEX "${schema}"."${name}"`);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, message: `Index ${name} dropped` }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  server.tool("list_indexes", "List indexes for a table", {
    table: z.string().describe("Table name"),
    schema: z.string().optional()
  }, async ({ table, schema = "public" }) => {
    const result = await executeQuery(`
      SELECT 
        i.indexname,
        i.indexdef,
        pg_size_pretty(pg_relation_size(quote_ident(i.schemaname) || '.' || quote_ident(i.indexname))) as size
      FROM pg_indexes i
      WHERE i.schemaname = $1 AND i.tablename = $2
    `, [schema, table]);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  // ============ CRUD HELPERS ============

  server.tool("insert_row", "Insert a row into a table", {
    table: z.string().describe("Table name"),
    data: z.record(z.any()).describe("Column-value pairs"),
    schema: z.string().optional(),
    returning: z.array(z.string()).optional().describe("Columns to return")
  }, async ({ table, data, schema = "public", returning }) => {
    const columns = Object.keys(data);
    const values = Object.values(data);
    const placeholders = columns.map((_, i) => `$${i + 1}`);
    
    let query = `INSERT INTO "${schema}"."${table}" (${columns.map(c => `"${c}"`).join(", ")}) VALUES (${placeholders.join(", ")})`;
    if (returning) query += ` RETURNING ${returning.map(c => `"${c}"`).join(", ")}`;
    
    try {
      const result = await executeQuery(query, values);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, rowCount: result.rowCount, rows: result.rows }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  server.tool("update_rows", "Update rows in a table", {
    table: z.string().describe("Table name"),
    data: z.record(z.any()).describe("Column-value pairs to update"),
    where: z.string().describe("WHERE condition (without WHERE keyword)"),
    whereParams: z.array(z.any()).optional().describe("Parameters for WHERE condition"),
    schema: z.string().optional()
  }, async ({ table, data, where, whereParams = [], schema = "public" }) => {
    const columns = Object.keys(data);
    const values = Object.values(data);
    const setClauses = columns.map((col, i) => `"${col}" = $${i + 1}`);
    
    // Adjust WHERE parameter placeholders
    const adjustedWhere = where.replace(/\$(\d+)/g, (_, num) => `$${parseInt(num) + columns.length}`);
    
    const query = `UPDATE "${schema}"."${table}" SET ${setClauses.join(", ")} WHERE ${adjustedWhere}`;
    
    try {
      const result = await executeQuery(query, [...values, ...whereParams]);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, rowCount: result.rowCount }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message, query }, null, 2) }] };
    }
  });

  server.tool("delete_rows", "Delete rows from a table", {
    table: z.string().describe("Table name"),
    where: z.string().describe("WHERE condition (without WHERE keyword)"),
    params: z.array(z.any()).optional(),
    schema: z.string().optional()
  }, async ({ table, where, params = [], schema = "public" }) => {
    const query = `DELETE FROM "${schema}"."${table}" WHERE ${where}`;
    
    try {
      const result = await executeQuery(query, params);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, rowCount: result.rowCount }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  server.tool("select_rows", "Select rows from a table with filtering", {
    table: z.string().describe("Table name"),
    columns: z.array(z.string()).optional().describe("Columns to select (default: all)"),
    where: z.string().optional().describe("WHERE condition"),
    params: z.array(z.any()).optional(),
    orderBy: z.string().optional(),
    limit: z.number().optional(),
    offset: z.number().optional(),
    schema: z.string().optional()
  }, async ({ table, columns = ["*"], where, params = [], orderBy, limit, offset, schema = "public" }) => {
    let query = `SELECT ${columns.join(", ")} FROM "${schema}"."${table}"`;
    if (where) query += ` WHERE ${where}`;
    if (orderBy) query += ` ORDER BY ${orderBy}`;
    if (limit) query += ` LIMIT ${limit}`;
    if (offset) query += ` OFFSET ${offset}`;
    
    try {
      const result = await executeQuery(query, params);
      return { content: [{ type: "text", text: formatResults(result) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  // ============ ANALYSIS TOOLS ============

  server.tool("explain_query", "Get query execution plan", {
    query: z.string().describe("SQL query to analyze"),
    analyze: z.boolean().optional().describe("Actually run the query to get real statistics"),
    buffers: z.boolean().optional().describe("Include buffer usage"),
    format: z.enum(["text", "json", "yaml", "xml"]).optional()
  }, async ({ query, analyze = false, buffers = false, format = "text" }) => {
    let explainQuery = `EXPLAIN (FORMAT ${format}`;
    if (analyze) explainQuery += ", ANALYZE";
    if (buffers) explainQuery += ", BUFFERS";
    explainQuery += `) ${query}`;
    
    try {
      const result = await executeQuery(explainQuery);
      return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  server.tool("get_table_stats", "Get table statistics", {
    table: z.string().describe("Table name"),
    schema: z.string().optional()
  }, async ({ table, schema = "public" }) => {
    const result = await executeQuery(`
      SELECT 
        relname as table_name,
        n_live_tup as live_rows,
        n_dead_tup as dead_rows,
        n_mod_since_analyze as mods_since_analyze,
        last_vacuum,
        last_autovacuum,
        last_analyze,
        last_autoanalyze
      FROM pg_stat_user_tables
      WHERE schemaname = $1 AND relname = $2
    `, [schema, table]);
    return { content: [{ type: "text", text: JSON.stringify(result.rows[0] || {}, null, 2) }] };
  });

  server.tool("get_active_connections", "Get active database connections", {}, async () => {
    const result = await executeQuery(`
      SELECT 
        pid,
        usename,
        application_name,
        client_addr,
        state,
        query,
        backend_start,
        query_start
      FROM pg_stat_activity
      WHERE datname = current_database()
      ORDER BY backend_start DESC
    `);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  server.tool("get_slow_queries", "Get slow/long-running queries", {
    minDurationSeconds: z.number().optional().describe("Minimum query duration in seconds")
  }, async ({ minDurationSeconds = 5 }) => {
    const result = await executeQuery(`
      SELECT 
        pid,
        usename,
        query,
        state,
        EXTRACT(EPOCH FROM (now() - query_start)) as duration_seconds,
        query_start
      FROM pg_stat_activity
      WHERE datname = current_database()
        AND state != 'idle'
        AND query_start IS NOT NULL
        AND EXTRACT(EPOCH FROM (now() - query_start)) > $1
      ORDER BY duration_seconds DESC
    `, [minDurationSeconds]);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  // ============ BACKUP & MAINTENANCE ============

  server.tool("vacuum_table", "Run VACUUM on a table", {
    table: z.string().describe("Table name"),
    schema: z.string().optional(),
    full: z.boolean().optional().describe("Run FULL vacuum (locks table)"),
    analyze: z.boolean().optional().describe("Update statistics")
  }, async ({ table, schema = "public", full = false, analyze = false }) => {
    let query = "VACUUM";
    if (full) query += " FULL";
    if (analyze) query += " ANALYZE";
    query += ` "${schema}"."${table}"`;
    
    try {
      await executeQuery(query);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, message: `VACUUM completed on ${schema}.${table}` }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  server.tool("reindex", "Rebuild indexes", {
    target: z.enum(["table", "index", "database"]),
    name: z.string().describe("Table, index, or database name"),
    schema: z.string().optional()
  }, async ({ target, name, schema = "public" }) => {
    let query = `REINDEX ${target.toUpperCase()} `;
    if (target === "table" || target === "index") {
      query += `"${schema}"."${name}"`;
    } else {
      query += `"${name}"`;
    }
    
    try {
      await executeQuery(query);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, message: `REINDEX completed` }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  // ============ SEQUENCES ============

  server.tool("list_sequences", "List all sequences", {
    schema: z.string().optional()
  }, async ({ schema = "public" }) => {
    const result = await executeQuery(`
      SELECT 
        sequencename,
        last_value,
        start_value,
        increment_by,
        max_value,
        min_value,
        cycle
      FROM pg_sequences
      WHERE schemaname = $1
    `, [schema]);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  server.tool("get_sequence_value", "Get current value of a sequence", {
    sequence: z.string().describe("Sequence name"),
    schema: z.string().optional()
  }, async ({ sequence, schema = "public" }) => {
    const result = await executeQuery(`SELECT currval('"${schema}"."${sequence}"')`);
    return { content: [{ type: "text", text: JSON.stringify({ value: result.rows[0].currval }, null, 2) }] };
  });

  server.tool("set_sequence_value", "Set sequence value", {
    sequence: z.string().describe("Sequence name"),
    value: z.number().describe("New value"),
    schema: z.string().optional()
  }, async ({ sequence, value, schema = "public" }) => {
    const result = await executeQuery(`SELECT setval('"${schema}"."${sequence}"', $1)`, [value]);
    return { content: [{ type: "text", text: JSON.stringify({ success: true, value: result.rows[0].setval }, null, 2) }] };
  });

  // ============ EXTENSIONS ============

  server.tool("list_extensions", "List installed extensions", {}, async () => {
    const result = await executeQuery(`
      SELECT extname, extversion, extnamespace::regnamespace as schema
      FROM pg_extension
      ORDER BY extname
    `);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  server.tool("list_available_extensions", "List available extensions", {}, async () => {
    const result = await executeQuery(`
      SELECT name, default_version, comment
      FROM pg_available_extensions
      WHERE installed_version IS NULL
      ORDER BY name
    `);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  server.tool("create_extension", "Install an extension", {
    name: z.string().describe("Extension name"),
    schema: z.string().optional()
  }, async ({ name, schema }) => {
    let query = `CREATE EXTENSION IF NOT EXISTS "${name}"`;
    if (schema) query += ` SCHEMA "${schema}"`;
    
    try {
      await executeQuery(query);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, message: `Extension ${name} installed` }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }] };
    }
  });

  // ============ USERS & PERMISSIONS ============

  server.tool("list_roles", "List database roles/users", {}, async () => {
    const result = await executeQuery(`
      SELECT 
        rolname,
        rolsuper,
        rolcreatedb,
        rolcreaterole,
        rolcanlogin,
        rolconnlimit,
        rolvaliduntil
      FROM pg_roles
      WHERE rolname NOT LIKE 'pg_%'
      ORDER BY rolname
    `);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  server.tool("get_table_permissions", "Get permissions for a table", {
    table: z.string().describe("Table name"),
    schema: z.string().optional()
  }, async ({ table, schema = "public" }) => {
    const result = await executeQuery(`
      SELECT 
        grantee,
        privilege_type,
        is_grantable
      FROM information_schema.table_privileges
      WHERE table_schema = $1 AND table_name = $2
    `, [schema, table]);
    return { content: [{ type: "text", text: JSON.stringify(result.rows, null, 2) }] };
  });

  return server;
}

// CORS middleware
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept");
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }
  next();
});

// Skip JSON parsing for /messages - SSEServerTransport handles it
app.use((req, res, next) => {
  if (req.path === "/messages") {
    return next();
  }
  express.json()(req, res, next);
});

// SSE endpoint
app.get("/sse", async (req: Request, res: Response) => {
  console.log("SSE connection request received");
  
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  const transport = new SSEServerTransport("/messages", res);
  const sessionId = transport.sessionId;
  transports[sessionId] = transport;
  
  console.log(`SSE session created: ${sessionId}`);

  const mcpServer = createMcpServer();
  
  transport.onclose = () => {
    console.log(`SSE session closed: ${sessionId}`);
    delete transports[sessionId];
  };

  try {
    await mcpServer.connect(transport);
    console.log(`MCP server connected to SSE session: ${sessionId}`);
  } catch (error) {
    console.error("SSE connection error:", error);
    delete transports[sessionId];
    if (!res.headersSent) {
      res.status(500).end();
    }
  }
});

// Messages endpoint
app.post("/messages", async (req: Request, res: Response) => {
  const sessionId = req.query.sessionId as string;
  console.log(`Message received for session: ${sessionId}`);
  
  if (!sessionId) {
    return res.status(400).json({ error: "Missing sessionId" });
  }

  const transport = transports[sessionId];
  if (!transport) {
    return res.status(404).json({ error: "Session not found" });
  }

  try {
    await transport.handlePostMessage(req, res);
  } catch (error) {
    console.error("Message handling error:", error);
    if (!res.headersSent) {
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

// Health check
app.get("/health", async (req, res) => {
  let dbStatus = "unknown";
  try {
    await pool.query("SELECT 1");
    dbStatus = "connected";
  } catch {
    dbStatus = "disconnected";
  }
  
  res.json({
    status: "ok",
    database: dbStatus,
    sessions: Object.keys(transports).length,
    version: "1.0.0"
  });
});

// Root endpoint
app.get("/", (req, res) => {
  res.json({
    name: "PostgreSQL MCP Server",
    version: "1.0.0",
    endpoints: {
      sse: "/sse",
      messages: "/messages",
      health: "/health"
    },
    tools: [
      // Connection & Info
      "test_connection", "get_database_info",
      // Schema
      "list_schemas", "list_tables", "describe_table", "list_views", "list_functions",
      // Queries
      "execute_query", "execute_write", "execute_transaction",
      // Table Operations
      "create_table", "drop_table", "alter_table", "truncate_table",
      // Indexes
      "create_index", "drop_index", "list_indexes",
      // CRUD
      "insert_row", "update_rows", "delete_rows", "select_rows",
      // Analysis
      "explain_query", "get_table_stats", "get_active_connections", "get_slow_queries",
      // Maintenance
      "vacuum_table", "reindex",
      // Sequences
      "list_sequences", "get_sequence_value", "set_sequence_value",
      // Extensions
      "list_extensions", "list_available_extensions", "create_extension",
      // Users & Permissions
      "list_roles", "get_table_permissions"
    ],
    environment: {
      DATABASE_URL: process.env.DATABASE_URL ? "configured" : "missing",
      DATABASE_SSL: process.env.DATABASE_SSL || "false"
    }
  });
});

// Graceful shutdown
process.on("SIGTERM", async () => {
  console.log("Shutting down...");
  await pool.end();
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`PostgreSQL MCP Server running on port ${PORT}`);
  console.log(`Database URL: ${process.env.DATABASE_URL ? "configured" : "NOT CONFIGURED"}`);
});
