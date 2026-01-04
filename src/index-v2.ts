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
const transports: Record&lt;string, SSEServerTransport&gt; = {};

// Helper function to execute queries safely
async function executeQuery(query: string, params?: any[]): Promise&lt;QueryResult&gt; {
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
    fields: result.fields?.map(f =&gt; ({ name: f.name, dataType: f.dataTypeID }))
  }, null, 2);
}

// Create and configure MCP server
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "postgresql-mcp-server",
    version: "1.0.0",
  });

  // ============ CONNECTION &amp; INFO TOOLS ============

  server.tool("test_connection", "Test database connection", {}, async () =&gt; {
    try {
      const result = await executeQuery("SELECT NOW() as current_time, current_database() as database, current_user as user, version() as version");
      return { content: [{ type: "text", text: JSON.stringify({ success: true, ...result.rows[0] }, null, 2) }] };
    } catch (error: any) {
      return { content: [{ type: "text", text: JSON.stringify({ success: false, error: error.message }, null, 2) }] };
    }
  });

  server.tool("get_database_info", "Get database information and statistics", {}, async () =&gt; {
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

  return server;
}

app.listen(PORT, () =&gt; {
  console.log(`PostgreSQL MCP Server running on port ${PORT}`);
});
