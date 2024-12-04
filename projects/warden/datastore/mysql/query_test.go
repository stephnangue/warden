package datastore

import (
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"vitess.io/vitess/go/mysql/collations"
	"vitess.io/vitess/go/mysql/sqlerror"
	"vitess.io/vitess/go/sqltypes"
	querypb "vitess.io/vitess/go/vt/proto/query"
)

// This test has been added to verify that IO errors in a connection lead to SQL Server lost errors
// So that we end up closing the connection higher up the stack and not reusing it.
// This test was added in response to a panic that was run into.
func TestSQLErrorOnServerClose(t *testing.T) {
	// Create socket pair for the server and client
	listener, sConn, cConn := createSocketPair(t)
	defer func() {
		listener.Close()
		sConn.Close()
		cConn.Close()
	}()

	err := cConn.WriteComQuery("close before rows read")
	require.NoError(t, err)

	handler := &testRun{t: t}
	_ = sConn.handleNextCommand(handler)

	// From the server we will receive a field packet which the client will read
	// At that point, if the server crashes and closes the connection.
	// We should be getting a Connection lost error.
	_, _, _, err = cConn.ReadQueryResult(100, true)
	require.Error(t, err)
	require.True(t, sqlerror.IsConnLostDuringQuery(err), err.Error())
}

func TestQueries(t *testing.T) {
	listener, sConn, cConn := createSocketPair(t)
	defer func() {
		listener.Close()
		sConn.Close()
		cConn.Close()
	}()

	// Smallest result
	checkQuery(t, "tiny", sConn, cConn, &sqltypes.Result{})

	// Typical Insert result
	checkQuery(t, "insert", sConn, cConn, &sqltypes.Result{
		RowsAffected: 0x8010203040506070,
		InsertID:     0x0102030405060708,
	})

	// Typical Select with TYPE_AND_NAME.
	// One value is also NULL.
	checkQuery(t, "type and name", sConn, cConn, &sqltypes.Result{
		Fields: []*querypb.Field{
			{
				Name:    "id",
				Type:    querypb.Type_INT32,
				Charset: collations.CollationBinaryID,
				Flags:   uint32(querypb.MySqlFlag_NUM_FLAG),
			},
			{
				Name:    "name",
				Type:    querypb.Type_VARCHAR,
				Charset: uint32(collations.MySQL8().DefaultConnectionCharset()),
			},
		},
		Rows: [][]sqltypes.Value{
			{
				sqltypes.MakeTrusted(querypb.Type_INT32, []byte("10")),
				sqltypes.MakeTrusted(querypb.Type_VARCHAR, []byte("nice name")),
			},
			{
				sqltypes.MakeTrusted(querypb.Type_INT32, []byte("20")),
				sqltypes.NULL,
			},
		},
	})

	// Typical Select with TYPE_AND_NAME.
	// All types are represented.
	// One row has all NULL values.
	checkQuery(t, "all types", sConn, cConn, &sqltypes.Result{
		Fields: []*querypb.Field{
			{Name: "Type_INT8     ", Type: querypb.Type_INT8, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG)},
			{Name: "Type_UINT8    ", Type: querypb.Type_UINT8, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG | querypb.MySqlFlag_UNSIGNED_FLAG)},
			{Name: "Type_INT16    ", Type: querypb.Type_INT16, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG)},
			{Name: "Type_UINT16   ", Type: querypb.Type_UINT16, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG | querypb.MySqlFlag_UNSIGNED_FLAG)},
			{Name: "Type_INT24    ", Type: querypb.Type_INT24, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG)},
			{Name: "Type_UINT24   ", Type: querypb.Type_UINT24, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG | querypb.MySqlFlag_UNSIGNED_FLAG)},
			{Name: "Type_INT32    ", Type: querypb.Type_INT32, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG)},
			{Name: "Type_UINT32   ", Type: querypb.Type_UINT32, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG | querypb.MySqlFlag_UNSIGNED_FLAG)},
			{Name: "Type_INT64    ", Type: querypb.Type_INT64, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG)},
			{Name: "Type_UINT64   ", Type: querypb.Type_UINT64, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG | querypb.MySqlFlag_UNSIGNED_FLAG)},
			{Name: "Type_FLOAT32  ", Type: querypb.Type_FLOAT32, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG)},
			{Name: "Type_FLOAT64  ", Type: querypb.Type_FLOAT64, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG)},
			{Name: "Type_TIMESTAMP", Type: querypb.Type_TIMESTAMP, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_BINARY_FLAG | querypb.MySqlFlag_TIMESTAMP_FLAG)},
			{Name: "Type_DATE     ", Type: querypb.Type_DATE, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_BINARY_FLAG)},
			{Name: "Type_TIME     ", Type: querypb.Type_TIME, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_BINARY_FLAG)},
			{Name: "Type_DATETIME ", Type: querypb.Type_DATETIME, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_BINARY_FLAG)},
			{Name: "Type_YEAR     ", Type: querypb.Type_YEAR, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_UNSIGNED_FLAG | querypb.MySqlFlag_NUM_FLAG)},
			{Name: "Type_DECIMAL  ", Type: querypb.Type_DECIMAL, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_NUM_FLAG)},
			{Name: "Type_TEXT     ", Type: querypb.Type_TEXT, Charset: uint32(collations.MySQL8().DefaultConnectionCharset())},
			{Name: "Type_BLOB     ", Type: querypb.Type_BLOB, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_BINARY_FLAG)},
			{Name: "Type_VARCHAR  ", Type: querypb.Type_VARCHAR, Charset: uint32(collations.MySQL8().DefaultConnectionCharset())},
			{Name: "Type_VARBINARY", Type: querypb.Type_VARBINARY, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_BINARY_FLAG)},
			{Name: "Type_CHAR     ", Type: querypb.Type_CHAR, Charset: uint32(collations.MySQL8().DefaultConnectionCharset())},
			{Name: "Type_BINARY   ", Type: querypb.Type_BINARY, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_BINARY_FLAG)},
			{Name: "Type_BIT      ", Type: querypb.Type_BIT, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_BINARY_FLAG)},
			{Name: "Type_ENUM     ", Type: querypb.Type_ENUM, Charset: uint32(collations.MySQL8().DefaultConnectionCharset()), Flags: uint32(querypb.MySqlFlag_ENUM_FLAG)},
			{Name: "Type_SET      ", Type: querypb.Type_SET, Charset: uint32(collations.MySQL8().DefaultConnectionCharset()), Flags: uint32(querypb.MySqlFlag_SET_FLAG)},
			// Skip TUPLE, not possible in Result.
			{Name: "Type_GEOMETRY ", Type: querypb.Type_GEOMETRY, Charset: collations.CollationBinaryID, Flags: uint32(querypb.MySqlFlag_BINARY_FLAG | querypb.MySqlFlag_BLOB_FLAG)},
			{Name: "Type_JSON     ", Type: querypb.Type_JSON, Charset: collations.CollationUtf8mb4ID},
			{Name: "Type_VECTOR   ", Type: querypb.Type_VECTOR, Charset: collations.CollationBinaryID},
		},
		Rows: [][]sqltypes.Value{
			{
				sqltypes.MakeTrusted(querypb.Type_INT8, []byte("Type_INT8")),
				sqltypes.MakeTrusted(querypb.Type_UINT8, []byte("Type_UINT8")),
				sqltypes.MakeTrusted(querypb.Type_INT16, []byte("Type_INT16")),
				sqltypes.MakeTrusted(querypb.Type_UINT16, []byte("Type_UINT16")),
				sqltypes.MakeTrusted(querypb.Type_INT24, []byte("Type_INT24")),
				sqltypes.MakeTrusted(querypb.Type_UINT24, []byte("Type_UINT24")),
				sqltypes.MakeTrusted(querypb.Type_INT32, []byte("Type_INT32")),
				sqltypes.MakeTrusted(querypb.Type_UINT32, []byte("Type_UINT32")),
				sqltypes.MakeTrusted(querypb.Type_INT64, []byte("Type_INT64")),
				sqltypes.MakeTrusted(querypb.Type_UINT64, []byte("Type_UINT64")),
				sqltypes.MakeTrusted(querypb.Type_FLOAT32, []byte("Type_FLOAT32")),
				sqltypes.MakeTrusted(querypb.Type_FLOAT64, []byte("Type_FLOAT64")),
				sqltypes.MakeTrusted(querypb.Type_TIMESTAMP, []byte("Type_TIMESTAMP")),
				sqltypes.MakeTrusted(querypb.Type_DATE, []byte("Type_DATE")),
				sqltypes.MakeTrusted(querypb.Type_TIME, []byte("Type_TIME")),
				sqltypes.MakeTrusted(querypb.Type_DATETIME, []byte("Type_DATETIME")),
				sqltypes.MakeTrusted(querypb.Type_YEAR, []byte("Type_YEAR")),
				sqltypes.MakeTrusted(querypb.Type_DECIMAL, []byte("Type_DECIMAL")),
				sqltypes.MakeTrusted(querypb.Type_TEXT, []byte("Type_TEXT")),
				sqltypes.MakeTrusted(querypb.Type_BLOB, []byte("Type_BLOB")),
				sqltypes.MakeTrusted(querypb.Type_VARCHAR, []byte("Type_VARCHAR")),
				sqltypes.MakeTrusted(querypb.Type_VARBINARY, []byte("Type_VARBINARY")),
				sqltypes.MakeTrusted(querypb.Type_CHAR, []byte("Type_CHAR")),
				sqltypes.MakeTrusted(querypb.Type_BINARY, []byte("Type_BINARY")),
				sqltypes.MakeTrusted(querypb.Type_BIT, []byte("Type_BIT")),
				sqltypes.MakeTrusted(querypb.Type_ENUM, []byte("Type_ENUM")),
				sqltypes.MakeTrusted(querypb.Type_SET, []byte("Type_SET")),
				sqltypes.MakeTrusted(querypb.Type_GEOMETRY, []byte("Type_GEOMETRY")),
				sqltypes.MakeTrusted(querypb.Type_JSON, []byte("Type_JSON")),
				sqltypes.MakeTrusted(querypb.Type_VECTOR, []byte("Type_VECTOR")),
			},
			{
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
				sqltypes.NULL,
			},
		},
	})

	// Typical Select with TYPE_AND_NAME.
	// First value first column is an empty string, so it's encoded as 0.
	checkQuery(t, "first empty string", sConn, cConn, &sqltypes.Result{
		Fields: []*querypb.Field{
			{
				Name:    "name",
				Type:    querypb.Type_VARCHAR,
				Charset: uint32(collations.MySQL8().DefaultConnectionCharset()),
			},
		},
		Rows: [][]sqltypes.Value{
			{
				sqltypes.MakeTrusted(querypb.Type_VARCHAR, []byte("")),
			},
			{
				sqltypes.MakeTrusted(querypb.Type_VARCHAR, []byte("nice name")),
			},
		},
	})

	// Typical Select with TYPE_ONLY.
	checkQuery(t, "type only", sConn, cConn, &sqltypes.Result{
		Fields: []*querypb.Field{
			{
				Type:    querypb.Type_INT64,
				Charset: collations.CollationBinaryID,
				Flags:   uint32(querypb.MySqlFlag_NUM_FLAG),
			},
		},
		Rows: [][]sqltypes.Value{
			{
				sqltypes.MakeTrusted(querypb.Type_INT64, []byte("10")),
			},
			{
				sqltypes.MakeTrusted(querypb.Type_INT64, []byte("20")),
			},
		},
	})

	// Typical Select with ALL.
	checkQuery(t, "complete", sConn, cConn, &sqltypes.Result{
		Fields: []*querypb.Field{
			{
				Type:         querypb.Type_INT64,
				Name:         "cool column name",
				Table:        "table name",
				OrgTable:     "org table",
				Database:     "fine db",
				OrgName:      "crazy org",
				ColumnLength: 0x80020304,
				Charset:      0x1234,
				Decimals:     36,
				Flags: uint32(querypb.MySqlFlag_NOT_NULL_FLAG |
					querypb.MySqlFlag_PRI_KEY_FLAG |
					querypb.MySqlFlag_PART_KEY_FLAG |
					querypb.MySqlFlag_NUM_FLAG),
			},
		},
		Rows: [][]sqltypes.Value{
			{
				sqltypes.MakeTrusted(querypb.Type_INT64, []byte("10")),
			},
			{
				sqltypes.MakeTrusted(querypb.Type_INT64, []byte("20")),
			},
			{
				sqltypes.MakeTrusted(querypb.Type_INT64, []byte("30")),
			},
		},
	})
}

func checkQuery(t *testing.T, query string, sConn, cConn *Conn, result *sqltypes.Result) {
	// The protocol depends on the CapabilityClientDeprecateEOF flag.
	// So we want to test both cases.

	sConn.Capabilities = 0
	cConn.Capabilities = 0
	checkQueryInternal(t, query, sConn, cConn, result, true /* wantfields */, true /* allRows */, false /* warnings */)
	checkQueryInternal(t, query, sConn, cConn, result, false /* wantfields */, true /* allRows */, false /* warnings */)
	checkQueryInternal(t, query, sConn, cConn, result, true /* wantfields */, false /* allRows */, false /* warnings */)
	checkQueryInternal(t, query, sConn, cConn, result, false /* wantfields */, false /* allRows */, false /* warnings */)

	checkQueryInternal(t, query, sConn, cConn, result, true /* wantfields */, true /* allRows */, true /* warnings */)

	sConn.Capabilities = CapabilityClientDeprecateEOF
	cConn.Capabilities = CapabilityClientDeprecateEOF
	checkQueryInternal(t, query, sConn, cConn, result, true /* wantfields */, true /* allRows */, false /* warnings */)
	checkQueryInternal(t, query, sConn, cConn, result, false /* wantfields */, true /* allRows */, false /* warnings */)
	checkQueryInternal(t, query, sConn, cConn, result, true /* wantfields */, false /* allRows */, false /* warnings */)
	checkQueryInternal(t, query, sConn, cConn, result, false /* wantfields */, false /* allRows */, false /* warnings */)

	checkQueryInternal(t, query, sConn, cConn, result, true /* wantfields */, true /* allRows */, true /* warnings */)
}

func checkQueryInternal(t *testing.T, query string, sConn, cConn *Conn, result *sqltypes.Result, wantfields, allRows, warnings bool) {

	if sConn.Capabilities&CapabilityClientDeprecateEOF > 0 {
		query += " NOEOF"
	} else {
		query += " EOF"
	}
	if wantfields {
		query += " FIELDS"
	} else {
		query += " NOFIELDS"
	}
	if allRows {
		query += " ALL"
	} else {
		query += " PARTIAL"
	}

	var warningCount uint16
	if warnings {
		query += " WARNINGS"
		warningCount = 99
	} else {
		query += " NOWARNINGS"
	}

	var fatalError string
	// Use a go routine to run ExecuteFetch.
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		maxrows := 10000
		if !allRows {
			// Asking for just one row max. The results that have more will fail.
			maxrows = 1
		}
		got, gotWarnings, err := cConn.ExecuteFetchWithWarningCount(query, maxrows, wantfields)
		if !allRows && len(result.Rows) > 1 {
			require.ErrorContains(t, err, "Row count exceeded")
			return
		}
		if err != nil {
			fatalError = fmt.Sprintf("executeFetch failed: %v", err)
			return
		}
		expected := *result
		if !wantfields {
			expected.Fields = nil
		}
		if !got.Equal(&expected) {
			for i, f := range got.Fields {
				if i < len(expected.Fields) && !proto.Equal(f, expected.Fields[i]) {
					t.Logf("Query = %v", query)
					t.Logf("Got      field(%v) = %v", i, f)
					t.Logf("Expected field(%v) = %v", i, expected.Fields[i])
				}
			}
			fatalError = fmt.Sprintf("ExecuteFetch(wantfields=%v) returned:\n%v\nBut was expecting:\n%v", wantfields, got, expected)
			return
		}

		if gotWarnings != warningCount {
			t.Errorf("ExecuteFetch(%v) expected %v warnings got %v", query, warningCount, gotWarnings)
			return
		}

		// Test ExecuteStreamFetch, build a Result.
		expected = *result
		if err := cConn.ExecuteStreamFetch(query); err != nil {
			fatalError = fmt.Sprintf("ExecuteStreamFetch(%v) failed: %v", query, err)
			return
		}
		got = &sqltypes.Result{}
		got.RowsAffected = result.RowsAffected
		got.InsertID = result.InsertID
		got.Fields, err = cConn.Fields()
		if err != nil {
			fatalError = fmt.Sprintf("Fields(%v) failed: %v", query, err)
			return
		}
		if len(got.Fields) == 0 {
			got.Fields = nil
		}
		for {
			row, err := cConn.FetchNext(nil)
			if err != nil {
				fatalError = fmt.Sprintf("FetchNext(%v) failed: %v", query, err)
				return
			}
			if row == nil {
				// Done.
				break
			}
			got.Rows = append(got.Rows, row)
		}
		cConn.CloseResult()

		if !got.Equal(&expected) {
			for i, f := range got.Fields {
				if i < len(expected.Fields) && !proto.Equal(f, expected.Fields[i]) {
					t.Logf("========== Got      field(%v) = %v", i, f)
					t.Logf("========== Expected field(%v) = %v", i, expected.Fields[i])
				}
			}
			for i, row := range got.Rows {
				if i < len(expected.Rows) && !reflect.DeepEqual(row, expected.Rows[i]) {
					t.Logf("========== Got      row(%v) = %v", i, RowString(row))
					t.Logf("========== Expected row(%v) = %v", i, RowString(expected.Rows[i]))
				}
			}
			if expected.RowsAffected != got.RowsAffected {
				t.Logf("========== Got      RowsAffected = %v", got.RowsAffected)
				t.Logf("========== Expected RowsAffected = %v", expected.RowsAffected)
			}
			t.Errorf("\nExecuteStreamFetch(%v) returned:\n%+v\nBut was expecting:\n%+v\n", query, got, &expected)
		}
	}()

	// The other side gets the request, and sends the result.
	// Twice, once for ExecuteFetch, once for ExecuteStreamFetch.
	count := 2
	if !allRows && len(result.Rows) > 1 {
		// short-circuit one test, the go routine returned and didn't
		// do the streaming query.
		count--
	}

	handler := testHandler{
		result:   result,
		warnings: warningCount,
	}

	for i := 0; i < count; i++ {
		kontinue := sConn.handleNextCommand(&handler)
		require.True(t, kontinue, "error handling command: %d", i)

	}

	wg.Wait()
	require.Equal(t, "", fatalError, fatalError)

}

func RowString(row []sqltypes.Value) string {
	l := len(row)
	result := fmt.Sprintf("%v values:", l)
	for _, val := range row {
		result += fmt.Sprintf(" %v", val)
	}
	return result
}
