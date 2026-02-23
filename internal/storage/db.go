package storage

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

// TODO: Integrate migrations when necessary

// OpenDb opens and runs the migrations for the sqlite3 database
func OpenDb(path string) (*sql.DB, error) {
	sqldb, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, err
	}

	if err := sqldb.Ping(); err != nil {
		return nil, err
	}

	if err := migrate(sqldb); err != nil {
		return nil, err
	}

	return sqldb, nil
}

// migrate creates the necessary tables
func migrate(db *sql.DB) error {
	_, err := db.Exec(`
          CREATE TABLE IF NOT EXISTS dns_queries (
              id          INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp   DATETIME NOT NULL,
              source_ip   TEXT NOT NULL,
              query_name  TEXT NOT NULL,
              query_type  TEXT NOT NULL,
			  cname_path  TEXT,
              response_ips TEXT,
			  request_type TEXT NOT NULL
          );
          CREATE INDEX IF NOT EXISTS idx_dns_queries_query_name ON dns_queries(query_name);
          CREATE INDEX IF NOT EXISTS idx_dns_queries_source_ip ON dns_queries(source_ip);
      `)
	return err
}

// InsertDNSEntry takes the relevant DNS information as parameters and inserts
// them to the sqlite3 database
func InsertDNSEntry(
	sqlDb *sql.DB,
	time, srcIP, queryName, queryType, cnamePath, responseIPs, responseType string,
) error {
	_, err := sqlDb.Exec(`
		INSERT INTO dns_queries
		(timestamp, source_ip, query_name, query_type, cname_path, response_ips, request_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7);`,
		time, srcIP, queryName, queryType, cnamePath, responseIPs, responseType)
	if err != nil {
		return err
	}
	return nil
}
