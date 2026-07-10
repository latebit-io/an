package utils

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latebit-io/an/internal/db"
)

var (
	testPostgres    *embeddedpostgres.EmbeddedPostgres
	testPort        uint32
	testRuntimePath string
)

// StartTestPostgres boots one embedded PostgreSQL server for a test package.
// Call it from TestMain via RunTestMain; each test then gets an isolated
// database from NewTestPool.
func StartTestPostgres() error {
	port, err := freePort()
	if err != nil {
		return err
	}
	testPort = port

	runtimePath, err := os.MkdirTemp("", "an-pg-")
	if err != nil {
		return err
	}
	testRuntimePath = runtimePath

	testPostgres = embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V17).
		Port(testPort).
		RuntimePath(runtimePath).
		DataPath(filepath.Join(runtimePath, "data")).
		Logger(os.Stderr))

	return testPostgres.Start()
}

// StopTestPostgres stops the package-level embedded server and removes its
// temp runtime directory.
func StopTestPostgres() error {
	if testPostgres == nil {
		return nil
	}
	err := testPostgres.Stop()
	if testRuntimePath != "" {
		_ = os.RemoveAll(testRuntimePath)
	}
	return err
}

// RunTestMain wraps m.Run with embedded PostgreSQL start/stop. Use from a
// package's TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(utils.RunTestMain(m)) }
func RunTestMain(m *testing.M) int {
	if err := StartTestPostgres(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start embedded postgres: %v\n", err)
		return 1
	}
	code := m.Run()
	if err := StopTestPostgres(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stop embedded postgres: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// NewTestPool creates a uniquely named database on the package's embedded
// server, runs all migrations against it and returns a connected pool. The
// pool is closed via t.Cleanup.
func NewTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testPostgres == nil {
		t.Fatal("embedded postgres not started: call utils.RunTestMain from TestMain")
	}

	ctx := context.Background()
	dbName := "an_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	admin, err := db.Connect(ctx, testConnString("postgres"))
	if err != nil {
		t.Fatalf("failed to connect to embedded postgres: %v", err)
	}
	defer admin.Close()

	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}

	pool, err := db.Connect(ctx, testConnString(dbName))
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("failed to migrate test database: %v", err)
	}
	return pool
}

func testConnString(database string) string {
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/%s?sslmode=disable", testPort, database)
}

func freePort() (uint32, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return uint32(listener.Addr().(*net.TCPAddr).Port), nil
}
