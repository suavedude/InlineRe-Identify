/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization.sqlproxy;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.delphix.dynamicmasking.onewaymasking.BatchMasker;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeRegistry;
import com.delphix.dynamicmasking.tokenization.key.DataEncryptionKeySource;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

/**
 * "SQL Interception" demo entry point: runs an arbitrary read-only query against the sample
 * Postgres and masks known-sensitive columns in the result transparently -- the query itself
 * never has to call {@code tokenize()}/{@code mask_*()} the way {@code docker/postgres/udf.sql}'s
 * SQL functions require. Distinct from that opt-in path, and from {@link
 * com.delphix.dynamicmasking.tokenization.http.TokenizationHttpServer}, which stays free of any
 * JDBC/Postgres-driver dependency on purpose.
 *
 * <p>Column matching is by {@link ResultSetMetaData#getColumnLabel}, case-insensitive, against a
 * fixed sensitive-column set -- there is deliberately no SQL parser here. An aliased sensitive
 * column (e.g. {@code SELECT email AS contact}) will not be recognized and passes through
 * unmasked; that is an accepted demo-scope tradeoff, not a bug (see README.md).
 *
 * <p>{@link #requireSafeSelect} rejects anything that isn't a plain {@code SELECT} (no stacked
 * statements, no write keywords), but this is a best-effort filter for a local single-user demo,
 * not a security boundary -- the same trust level as the existing "SQL Functions" tab's arbitrary
 * {@code psql} execution.
 *
 * <p>Env vars: {@code DB_HOST}, {@code DB_PORT} (default {@code 5432}), {@code DB_NAME},
 * {@code DB_USER}, {@code DB_PASSWORD} for the fixed JDBC target, plus {@code KEY_SOURCE} (+ its
 * {@link DataEncryptionKeySource} variants) for the one-way masking key -- no {@code
 * CRYPTO_PROVIDER}/{@code CIPHER_ALGORITHM} needed since one-way masking schemes don't take one.
 */
public final class SqlInterceptionHttpServer {

    /** Column label (lowercased) -> the fixed masking scheme id it's always masked with. */
    private static final Map<String, String> SENSITIVE_COLUMN_SCHEMES = new LinkedHashMap<>();

    static {
        SENSITIVE_COLUMN_SCHEMES.put("full_name", "FULL-NAME-MASK");
        SENSITIVE_COLUMN_SCHEMES.put("email", "EMAIL-MASK");
        SENSITIVE_COLUMN_SCHEMES.put("credit_card", "CREDIT-CARD-MASK");
    }

    private static final Pattern DENYLIST = Pattern.compile(
            "\\b(insert|update|delete|drop|alter|truncate|grant|copy|create)\\b");

    private final ObjectMapper mapper = new ObjectMapper();
    private final byte[] dataEncryptionKey;
    private final Map<String, OneWayMaskingScheme> sensitiveColumnSchemes;
    private final String jdbcUrl;
    private final String dbUser;
    private final String dbPassword;

    public SqlInterceptionHttpServer() {
        this.dataEncryptionKey = DataEncryptionKeySource.resolve();

        Map<String, OneWayMaskingScheme> resolved = new LinkedHashMap<>();
        SENSITIVE_COLUMN_SCHEMES.forEach((column, schemeId) ->
                resolved.put(column, OneWayMaskingSchemeRegistry.resolve(schemeId)));
        this.sensitiveColumnSchemes = resolved;

        String host = requireEnv("DB_HOST");
        String port = System.getenv().getOrDefault("DB_PORT", "5432");
        String dbName = requireEnv("DB_NAME");
        this.jdbcUrl = "jdbc:postgresql://" + host + ":" + port + "/" + dbName;
        this.dbUser = requireEnv("DB_USER");
        this.dbPassword = requireEnv("DB_PASSWORD");

        // Fail fast at startup on a bad DB config, same reasoning as resolving the DEK above --
        // a broken connection surfaces in container logs / orchestrator restart-looping rather
        // than as a 500 on the first request.
        try (Connection probe = openConnection()) {
            // no-op: opening and closing is the probe.
        } catch (SQLException e) {
            throw new IllegalStateException("Could not connect to " + jdbcUrl, e);
        }
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "4053"));
        SqlInterceptionHttpServer app = new SqlInterceptionHttpServer();

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/v1/query", app.queryHandler());
        server.createContext("/healthz", exchange -> respond(exchange, 200, "{\"status\":\"ok\"}"));
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("Listening on :" + port);
    }

    private Connection openConnection() throws SQLException {
        return DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
    }

    private HttpHandler queryHandler() {
        return exchange -> {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    respond(exchange, 405, "{\"error\":\"POST required\"}");
                    return;
                }
                handleQuery(exchange);
            } finally {
                exchange.close();
            }
        };
    }

    private void handleQuery(HttpExchange exchange) throws IOException {
        QueryRequest request;
        try {
            request = mapper.readValue(exchange.getRequestBody(), QueryRequest.class);
        } catch (Exception e) {
            respond(exchange, 400, "{\"error\":\"request body must be JSON matching {\\\"sql\\\": \\\"...\\\"}\"}");
            return;
        }
        if (request.sql == null || request.sql.isBlank()) {
            respond(exchange, 400, "{\"error\":\"'sql' is required\"}");
            return;
        }

        try {
            requireSafeSelect(request.sql);
            QueryResponse response = runQuery(request.sql);
            respond(exchange, 200, mapper.writeValueAsString(response));
        } catch (IllegalArgumentException e) {
            respond(exchange, 400, "{\"error\":" + mapper.writeValueAsString(e.getMessage()) + "}");
        } catch (SQLException e) {
            respond(exchange, 400, "{\"error\":" + mapper.writeValueAsString("query failed: " + e.getMessage()) + "}");
        }
    }

    /**
     * Rejects anything that isn't a plain, single {@code SELECT} statement. Best-effort only --
     * see the class javadoc's "not a security boundary" note.
     */
    static void requireSafeSelect(String sql) {
        String trimmed = sql.strip();
        String withoutTrailingSemicolon = trimmed.replaceAll(";\\s*$", "");
        if (withoutTrailingSemicolon.contains(";")) {
            throw new IllegalArgumentException("Stacked statements are not allowed");
        }
        String lower = withoutTrailingSemicolon.toLowerCase(Locale.ROOT);
        if (!lower.startsWith("select")) {
            throw new IllegalArgumentException("Only SELECT statements are allowed (SQL Interception is read-only)");
        }
        if (DENYLIST.matcher(lower).find()) {
            throw new IllegalArgumentException("Statement contains a disallowed keyword");
        }
    }

    private QueryResponse runQuery(String sql) throws SQLException {
        try (Connection conn = openConnection();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {
            ResultSetMetaData meta = rs.getMetaData();
            int columnCount = meta.getColumnCount();

            List<String> columns = new ArrayList<>(columnCount);
            List<OneWayMaskingScheme> columnSchemes = new ArrayList<>(columnCount);
            Set<String> maskedColumns = new LinkedHashSet<>();
            for (int i = 1; i <= columnCount; i++) {
                String label = meta.getColumnLabel(i);
                columns.add(label);
                OneWayMaskingScheme scheme = sensitiveColumnSchemes.get(label.toLowerCase(Locale.ROOT));
                columnSchemes.add(scheme);
                if (scheme != null) {
                    maskedColumns.add(label);
                }
            }

            List<List<String>> rows = new ArrayList<>();
            while (rs.next()) {
                List<String> row = new ArrayList<>(columnCount);
                for (int i = 1; i <= columnCount; i++) {
                    row.add(rs.getString(i));
                }
                rows.add(row);
            }

            // Mask column-wise (one BatchMasker.apply call per sensitive column across all rows)
            // rather than cell-by-cell, so this reuses the exact batch/null/failure-handling
            // logic every other entry point shares.
            for (int c = 0; c < columnCount; c++) {
                OneWayMaskingScheme scheme = columnSchemes.get(c);
                if (scheme == null) {
                    continue;
                }
                List<String> values = new ArrayList<>(rows.size());
                for (List<String> row : rows) {
                    values.add(row.get(c));
                }
                BatchMasker.Result result = BatchMasker.apply(values, scheme, dataEncryptionKey, null);
                for (int r = 0; r < rows.size(); r++) {
                    rows.get(r).set(c, result.results.get(r));
                }
            }

            QueryResponse response = new QueryResponse();
            response.columns = columns;
            response.rows = rows;
            response.maskedColumns = new ArrayList<>(maskedColumns);
            return response;
        }
    }

    private static void respond(HttpExchange exchange, int status, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            throw new IllegalStateException(name + " environment variable must be set");
        }
        return value;
    }

    static final class QueryRequest {
        public String sql;
    }

    static final class QueryResponse {
        public List<String> columns;
        public List<List<String>> rows;
        public List<String> maskedColumns;
    }
}
