package storage

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DNSMostQueriedDomain struct {
	QueryName string
	Events    string
	Count     int
}

type DNSEntry struct {
	Id          int
	Timestamp   time.Time
	SourceIP    string
	QueryName   string
	QueryType   string
	CNamePath   string
	ResponseIPs string
	RequestType string
	TxnId       uint16
}

// TODO: Integrate migrations when necessary

// OpenDb opens and runs the migrations for the sqlite3 database
func OpenDb(path string) (*sql.DB, error) {
	sqldb, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		log.Printf("opening")
		return nil, err
	}

	if err := sqldb.Ping(); err != nil {
		log.Printf("pinging")
		return nil, err
	}

	if err := migrate(sqldb); err != nil {
		log.Printf("migrating")
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
			  request_type TEXT NOT NULL,
		      event INTEGER
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
	eventNum uint16,
) error {
	_, err := sqlDb.Exec(`
		INSERT INTO dns_queries
		(timestamp, source_ip, query_name, query_type, cname_path, response_ips, request_type, event)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8);`,
		time, srcIP, queryName, queryType, cnamePath, responseIPs, responseType, eventNum)
	if err != nil {
		log.Printf("cannot insert: %v", err)
		return err
	}
	return nil
}

// GetMostQueriedDomains queries the database 'dns_queries' table to get:
// - Query Name
// - Events / DNS Txn Ids
// - Count
//
// Events/ Txn Ids are concat together to display all the Txn Ids associated
// with each DNS query
func GetMostQueriedDomains(sqlDb *sql.DB) ([]DNSMostQueriedDomain, error) {
	rows, err := sqlDb.Query(
		`SELECT
			query_name,
			GROUP_CONCAT(event) AS events,
			COUNT(*) AS count 
		FROM dns_queries 
		WHERE request_type = 'query'
		GROUP BY query_name
		ORDER BY count DESC`,
	)
	if err != nil {
		return nil, err
	}

	var mqd []DNSMostQueriedDomain
	for rows.Next() {
		var d DNSMostQueriedDomain
		if err := rows.Scan(&d.QueryName, &d.Events, &d.Count); err != nil {
			return nil, err
		}

		mqd = append(mqd, d)
	}

	return mqd, nil
}

func GetQueriesOverTime(sqlDb *sql.DB) error {
	return nil
}

func GetUniqueDomains(sqlDb *sql.DB) error {
	return nil
}

// GetDNSEntries wraps a 'SELECT *' statement for the dns_queries table
func GetDNSEntries(sqlDb *sql.DB) ([]DNSEntry, error) {
	rows, err := sqlDb.Query("SELECT * from dns_queries")
	if err != nil {
		return nil, err
	}

	var de []DNSEntry
	for rows.Next() {
		var e DNSEntry
		if err := rows.Scan(
			&e.Id,
			&e.Timestamp,
			&e.SourceIP,
			&e.QueryName,
			&e.QueryType,
			&e.CNamePath,
			&e.ResponseIPs,
			&e.RequestType,
			&e.TxnId,
		); err != nil {
			return nil, err
		}

		de = append(de, e)
	}

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	return de, nil
}
