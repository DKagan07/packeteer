package storage

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ******************************
// OpenDb
// ******************************

func TestOpenDb(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	require.NotNil(t, db)
	defer db.Close()
}

func TestOpenDb_CreatesTables(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	for _, table := range []string{"dns_queries", "alerts"} {
		var name string
		row := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table)
		err = row.Scan(&name)
		require.NoError(t, err, "table %q not found", table)
		assert.Equal(t, table, name)
	}
}

func TestOpenDb_InvalidPath(t *testing.T) {
	_, err := OpenDb("/nonexistent/path/to/db")
	assert.Error(t, err)
}

func TestOpenDb_Idempotent(t *testing.T) {
	path := t.TempDir() + "/test.db"

	db, err := OpenDb(path)
	require.NoError(t, err)
	err = InsertDNSEntry(
		db,
		"2024-01-01T00:00:00Z",
		"192.168.0.1",
		"example.com",
		"A",
		"",
		"1.2.3.4",
		"query",
		1,
	)
	require.NoError(t, err)
	db.Close()

	// Reopening an existing database should not error or lose existing data
	db2, err := OpenDb(path)
	require.NoError(t, err)
	defer db2.Close()

	var count int
	err = db2.QueryRow("SELECT COUNT(*) FROM dns_queries").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestOpenDb_CreatesIndexes(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	for _, idx := range []string{"idx_dns_queries_query_name", "idx_dns_queries_source_ip"} {
		var name string
		row := db.QueryRow("SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx)
		err := row.Scan(&name)
		require.NoError(t, err, "index %q not found", idx)
		assert.Equal(t, idx, name)
	}
}

// ******************************
// InsertDNSEntry
// ******************************

func TestInsertDNSEntry(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:00",
		"192.168.0.1",
		"example.com",
		"A",
		"",
		"1.2.3.4",
		"query",
		123,
	)
	assert.NoError(t, err)
}

func TestInsertDNSEntry_VerifyFields(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-01-01T00:00:00Z",
		"192.168.0.1",
		"example.com",
		"A",
		"cdn.example.com,",
		"1.2.3.4",
		"response",
		456,
	)
	require.NoError(t, err)

	var timestamp, srcIP, queryName, queryType, cnamePath, responseIPs, requestType string
	var event uint16
	row := db.QueryRow(
		"SELECT timestamp, source_ip, query_name, query_type, cname_path, response_ips, request_type, event FROM dns_queries LIMIT 1",
	)
	err = row.Scan(
		&timestamp,
		&srcIP,
		&queryName,
		&queryType,
		&cnamePath,
		&responseIPs,
		&requestType,
		&event,
	)
	require.NoError(t, err)

	assert.Equal(t, "2024-01-01T00:00:00Z", timestamp)
	assert.Equal(t, "192.168.0.1", srcIP)
	assert.Equal(t, "example.com", queryName)
	assert.Equal(t, "A", queryType)
	assert.Equal(t, "cdn.example.com,", cnamePath)
	assert.Equal(t, "1.2.3.4", responseIPs)
	assert.Equal(t, "response", requestType)
	assert.Equal(t, uint16(456), event)
}

func TestInsertDNSEntry_MultipleEntries(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	entries := []struct {
		time        string
		srcIP       string
		queryName   string
		queryType   string
		cnamePath   string
		responseIPs string
		requestType string
		event       uint16
	}{
		{"2024-01-01 00:00:00", "192.168.0.1", "example.com", "A", "", "1.2.3.4", "query", 1},
		{
			"2024-01-01 00:00:01",
			"192.168.0.2",
			"google.com",
			"AAAA",
			"",
			"2001:4860:4860::8888",
			"query",
			2,
		},
		{
			"2024-01-01 00:00:02",
			"192.168.0.1",
			"cdn.example.com",
			"A",
			"example.com,cdn.example.com,",
			"5.6.7.8",
			"response",
			3,
		},
	}

	for _, e := range entries {
		err := InsertDNSEntry(
			db,
			e.time,
			e.srcIP,
			e.queryName,
			e.queryType,
			e.cnamePath,
			e.responseIPs,
			e.requestType,
			e.event,
		)
		assert.NoError(t, err)
	}

	var count int
	row := db.QueryRow("SELECT COUNT(*) FROM dns_queries")
	err = row.Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestInsertDNSEntry_EmptyOptionalFields(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:00",
		"10.0.0.1",
		"example.com",
		"A",
		"",
		"",
		"query",
		2,
	)
	assert.NoError(t, err)
}

// ******************************
// InsertAlert
// ******************************

func TestInsertAlert(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertAlert(
		db,
		"2024-01-01 00:00:00",
		"PortScan",
		"high",
		"scan detected from 192.168.0.1",
	)
	assert.NoError(t, err)
}

func TestInsertAlert_VerifyFields(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertAlert(
		db,
		"2024-01-01T12:30:00Z",
		"PortScan",
		"high",
		"scan detected from 192.168.0.1",
	)
	require.NoError(t, err)

	var timestamp, ruleName, severity, details string
	row := db.QueryRow(
		"SELECT timestamp, rule_name, severity, details FROM alerts LIMIT 1",
	)
	err = row.Scan(&timestamp, &ruleName, &severity, &details)
	require.NoError(t, err)

	assert.Equal(t, "2024-01-01T12:30:00Z", timestamp)
	assert.Equal(t, "PortScan", ruleName)
	assert.Equal(t, "high", severity)
	assert.Equal(t, "scan detected from 192.168.0.1", details)
}

func TestInsertAlert_MultipleEntries(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	alerts := []struct {
		time     string
		ruleName string
		severity string
		details  string
	}{
		{"2024-01-01 00:00:00", "PortScan", "high", "scan from 10.0.0.1"},
		{"2024-01-01 00:01:00", "PortScan", "high", "scan from 10.0.0.2"},
		{"2024-01-01 00:02:00", "DNSTunnel", "medium", "suspicious DNS traffic"},
	}

	for _, a := range alerts {
		err := InsertAlert(db, a.time, a.ruleName, a.severity, a.details)
		assert.NoError(t, err)
	}

	var count int
	row := db.QueryRow("SELECT COUNT(*) FROM alerts")
	err = row.Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestInsertAlert_EmptyDetails(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertAlert(
		db,
		"2024-01-01 00:00:00",
		"PortScan",
		"low",
		"",
	)
	assert.NoError(t, err)
}

func TestInsertAlert_AutoIncrementsId(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	for i := range 3 {
		err = InsertAlert(
			db,
			fmt.Sprintf("2024-01-01 00:0%d:00", i),
			"PortScan",
			"high",
			"details",
		)
		require.NoError(t, err)
	}

	rows, err := db.Query("SELECT id FROM alerts ORDER BY id")
	require.NoError(t, err)

	var ids []int
	for rows.Next() {
		var id int
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.Len(t, ids, 3)
	assert.Equal(t, 1, ids[0])
	assert.Equal(t, 2, ids[1])
	assert.Equal(t, 3, ids[2])
}

// ******************************
// GetMostQueriedDomains
// ******************************

func TestGetMostQueriedDomains_Empty(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	results, err := GetMostQueriedDomains(db)
	assert.NoError(t, err)
	assert.Empty(t, results)
}

func TestGetMostQueriedDomains_Basic(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:00",
		"192.168.0.1",
		"example.com",
		"A",
		"",
		"",
		"query",
		1,
	)
	require.NoError(t, err)
	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:01",
		"192.168.0.1",
		"example.com",
		"A",
		"",
		"",
		"query",
		2,
	)
	require.NoError(t, err)
	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:02",
		"192.168.0.1",
		"google.com",
		"A",
		"",
		"",
		"query",
		3,
	)
	require.NoError(t, err)

	results, err := GetMostQueriedDomains(db)
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, "example.com", results[0].QueryName)
	assert.Equal(t, 2, results[0].Count)
	assert.Equal(t, "google.com", results[1].QueryName)
	assert.Equal(t, 1, results[1].Count)
}

func TestGetMostQueriedDomains_ExcludesResponses(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:00",
		"192.168.0.1",
		"example.com",
		"A",
		"",
		"1.2.3.4",
		"response",
		1,
	)
	require.NoError(t, err)
	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:01",
		"192.168.0.1",
		"google.com",
		"A",
		"",
		"",
		"query",
		2,
	)
	require.NoError(t, err)

	results, err := GetMostQueriedDomains(db)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "google.com", results[0].QueryName)
}

func TestGetMostQueriedDomains_EventsConcatenated(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:00",
		"192.168.0.1",
		"example.com",
		"A",
		"",
		"",
		"query",
		10,
	)
	require.NoError(t, err)
	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:01",
		"192.168.0.1",
		"example.com",
		"A",
		"",
		"",
		"query",
		20,
	)
	require.NoError(t, err)

	results, err := GetMostQueriedDomains(db)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Events, "10")
	assert.Contains(t, results[0].Events, "20")
	assert.Equal(t, 2, results[0].Count)
}

func TestGetMostQueriedDomains_OrderedByCountDesc(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	for i := range 3 {
		err = InsertDNSEntry(
			db,
			"2024-01-01 00:00:00",
			"192.168.0.1",
			"top.com",
			"A",
			"",
			"",
			"query",
			uint16(i),
		)
		require.NoError(t, err)
	}
	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:00",
		"192.168.0.1",
		"middle.com",
		"A",
		"",
		"",
		"query",
		10,
	)
	require.NoError(t, err)
	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:01",
		"192.168.0.1",
		"middle.com",
		"A",
		"",
		"",
		"query",
		11,
	)
	require.NoError(t, err)
	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:00",
		"192.168.0.1",
		"bottom.com",
		"A",
		"",
		"",
		"query",
		20,
	)
	require.NoError(t, err)

	results, err := GetMostQueriedDomains(db)
	require.NoError(t, err)
	require.Len(t, results, 3)
	assert.Equal(t, "top.com", results[0].QueryName)
	assert.Equal(t, "middle.com", results[1].QueryName)
	assert.Equal(t, "bottom.com", results[2].QueryName)
}

// ******************************
// GetDNSEntries
// ******************************

func TestGetDNSEntries_Empty(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	entries, err := GetDNSEntries(db)
	assert.NoError(t, err)
	assert.Empty(t, entries)
}

func TestGetDNSEntries_VerifyFields(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-01-01T00:00:00Z",
		"192.168.0.1",
		"example.com",
		"A",
		"cdn.example.com,",
		"1.2.3.4",
		"query",
		42,
	)
	require.NoError(t, err)

	entries, err := GetDNSEntries(db)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "192.168.0.1", e.SourceIP)
	assert.Equal(t, "example.com", e.QueryName)
	assert.Equal(t, "A", e.QueryType)
	assert.Equal(t, "cdn.example.com,", e.CNamePath)
	assert.Equal(t, "1.2.3.4", e.ResponseIPs)
	assert.Equal(t, "query", e.RequestType)
	assert.Equal(t, uint16(42), e.TxnId)
}

func TestGetDNSEntries_VerifyTimestamp(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-06-15T12:30:45Z",
		"192.168.0.1",
		"example.com",
		"A",
		"",
		"",
		"query",
		1,
	)
	require.NoError(t, err)

	entries, err := GetDNSEntries(db)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	ts := entries[0].Timestamp
	assert.Equal(t, 2024, ts.UTC().Year())
	assert.Equal(t, 6, int(ts.UTC().Month()))
	assert.Equal(t, 15, ts.UTC().Day())
	assert.Equal(t, 12, ts.UTC().Hour())
	assert.Equal(t, 30, ts.UTC().Minute())
	assert.Equal(t, 45, ts.UTC().Second())
}

func TestGetDNSEntries_MultipleEntries(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	for i := range 3 {
		err = InsertDNSEntry(
			db,
			"2024-01-01 00:00:00",
			"192.168.0.1",
			"example.com",
			"A",
			"",
			"",
			"query",
			uint16(i+1),
		)
		require.NoError(t, err)
	}

	entries, err := GetDNSEntries(db)
	require.NoError(t, err)
	assert.Len(t, entries, 3)
}

// ******************************
// GetQueriesOverTime
// ******************************

func TestGetQueriesOverTime_Empty(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	entries, err := GetQueriesOverTime(db)
	require.NoError(t, err)
	assert.Len(t, entries, 0)
}

func TestGetQueriesOverTime_VerifyFields(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-01-01T00:00:00Z",
		"192.168.0.1",
		"example.com",
		"A",
		"cdn.example.com,",
		"1.2.3.4",
		"query",
		42,
	)
	require.NoError(t, err)

	entries, err := GetQueriesOverTime(db)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	e := entries[0]
	assert := assert.New(t)
	assert.Equal(1, e.Count)
	assert.Equal("2024-01-01 00:00", e.Timestamp)
}

func TestGetQueriesOverTime_MultipleEntries(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	for i := range 3 {
		err = InsertDNSEntry(
			db,
			fmt.Sprintf("2024-01-01 00:0%d:00", i),
			"192.168.0.1",
			"example.com",
			"A",
			"",
			"",
			"query",
			uint16(i+1),
		)
		require.NoError(t, err)
	}

	entries, err := GetQueriesOverTime(db)

	assert := assert.New(t)
	require.NoError(t, err)
	assert.Len(entries, 3)
	assert.Equal(1, entries[0].Count)
	assert.Equal("2024-01-01 00:00", entries[0].Timestamp)
	assert.Equal(1, entries[1].Count)
	assert.Equal("2024-01-01 00:01", entries[1].Timestamp)
	assert.Equal(1, entries[2].Count)
	assert.Equal("2024-01-01 00:02", entries[2].Timestamp)
}

func TestGetQueriesOverTime_IncludesResponses(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:00",
		"192.168.0.1",
		"example.com",
		"A",
		"",
		"",
		"query",
		1,
	)
	require.NoError(t, err)
	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:30",
		"192.168.0.255",
		"example.com",
		"A",
		"",
		"1.2.3.4",
		"response",
		1,
	)
	require.NoError(t, err)

	entries, err := GetQueriesOverTime(db)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, 2, entries[0].Count)
}

func TestGetQueriesOverTime_MultipleEntriesSameTime(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	for i := range 2 {
		err = InsertDNSEntry(
			db,
			fmt.Sprintf("2024-01-01 00:0%d:00", i),
			"192.168.0.1",
			"example.com",
			"A",
			"",
			"",
			"query",
			uint16(i+1),
		)
		require.NoError(t, err)
	}

	err = InsertDNSEntry(
		db,
		fmt.Sprintf("2024-01-01 00:0%d:00", 1),
		"192.168.0.1",
		"example.com",
		"A",
		"",
		"",
		"query",
		uint16(3),
	)
	require.NoError(t, err)

	entries, err := GetQueriesOverTime(db)

	assert := assert.New(t)
	require.NoError(t, err)
	assert.Len(entries, 2)
	assert.Equal(1, entries[0].Count)
	assert.Equal(2, entries[1].Count)
}

// ******************************
// GetUniqueDomains
// ******************************

func TestGetUniqueDomains_Empty(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	entries, err := GetUniqueDomains(db)
	require.NoError(t, err)
	assert.Len(t, entries, 0)
}

func TestGetUniqueDomains_VerifyFields(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-01-01T00:00:00Z",
		"192.168.0.1",
		"example.com",
		"A",
		"cdn.example.com,",
		"1.2.3.4",
		"query",
		42,
	)
	require.NoError(t, err)

	entries, err := GetUniqueDomains(db)
	require.NoError(t, err)
	assert.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "192.168.0.1", e.SourceIP)
	assert.Equal(t, "example.com", e.QueryName)
	assert.Equal(t, "query", e.RequestType)
}

func TestGetUniqueDomains_MultipleFields(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	for i := range 3 {
		err = InsertDNSEntry(
			db,
			"2024-01-01 00:00:00",
			"192.168.0.1",
			"example.com",
			"A",
			"",
			"",
			"query",
			uint16(i+1),
		)
		require.NoError(t, err)
	}
	entries, err := GetUniqueDomains(db)
	require.NoError(t, err)

	assert := assert.New(t)
	assert.Len(entries, 1)

	e := entries[0]
	assert.Equal("192.168.0.1", e.SourceIP)
	assert.Equal("example.com", e.QueryName)
	assert.Equal("query", e.RequestType)
}

func TestGetUniqueDomains_Deduplication(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	for i := range 5 {
		err = InsertDNSEntry(
			db,
			"2024-01-01 00:00:00",
			"192.168.0.1",
			"example.com",
			"A",
			"",
			"",
			"query",
			uint16(i+1),
		)
		require.NoError(t, err)
	}

	entries, err := GetUniqueDomains(db)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestGetUniqueDomains_ReqestAndResponse(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:00",
		"192.168.0.1",
		"example.com",
		"A",
		"",
		"",
		"query",
		uint16(1),
	)
	require.NoError(t, err)

	err = InsertDNSEntry(
		db,
		"2024-01-01 00:00:00",
		"192.168.0.255",
		"example.com",
		"A",
		"",
		"",
		"response",
		uint16(1),
	)
	require.NoError(t, err)

	entries, err := GetUniqueDomains(db)
	require.NoError(t, err)

	assert := assert.New(t)
	assert.Len(entries, 2)

	e1 := entries[0]
	assert.Equal("192.168.0.1", e1.SourceIP)
	assert.Equal("example.com", e1.QueryName)
	assert.Equal("query", e1.RequestType)

	e2 := entries[1]
	assert.Equal("192.168.0.255", e2.SourceIP)
	assert.Equal("example.com", e2.QueryName)
	assert.Equal("response", e2.RequestType)
}
