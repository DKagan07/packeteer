package storage

import (
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

	var name string
	row := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='dns_queries'")
	err = row.Scan(&name)
	require.NoError(t, err)
	assert.Equal(t, "dns_queries", name)
}

func TestOpenDb_InvalidPath(t *testing.T) {
	_, err := OpenDb("/nonexistent/path/to/db")
	assert.Error(t, err)
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
	)
	require.NoError(t, err)

	var timestamp, srcIP, queryName, queryType, cnamePath, responseIPs, requestType string
	row := db.QueryRow(
		"SELECT timestamp, source_ip, query_name, query_type, cname_path, response_ips, request_type FROM dns_queries LIMIT 1",
	)
	err = row.Scan(
		&timestamp,
		&srcIP,
		&queryName,
		&queryType,
		&cnamePath,
		&responseIPs,
		&requestType,
	)
	require.NoError(t, err)

	assert.Equal(t, "2024-01-01T00:00:00Z", timestamp)
	assert.Equal(t, "192.168.0.1", srcIP)
	assert.Equal(t, "example.com", queryName)
	assert.Equal(t, "A", queryType)
	assert.Equal(t, "cdn.example.com,", cnamePath)
	assert.Equal(t, "1.2.3.4", responseIPs)
	assert.Equal(t, "response", requestType)
}

func TestInsertDNSEntry_MultipleEntries(t *testing.T) {
	db, err := OpenDb(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer db.Close()

	entries := []struct {
		time, srcIP, queryName, queryType, cnamePath, responseIPs, requestType string
	}{
		{"2024-01-01 00:00:00", "192.168.0.1", "example.com", "A", "", "1.2.3.4", "query"},
		{
			"2024-01-01 00:00:01",
			"192.168.0.2",
			"google.com",
			"AAAA",
			"",
			"2001:4860:4860::8888",
			"query",
		},
		{
			"2024-01-01 00:00:02",
			"192.168.0.1",
			"cdn.example.com",
			"A",
			"example.com,cdn.example.com,",
			"5.6.7.8",
			"response",
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

	err = InsertDNSEntry(db, "2024-01-01 00:00:00", "10.0.0.1", "example.com", "A", "", "", "query")
	assert.NoError(t, err)
}
