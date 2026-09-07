// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build !cgo

// A cgo-free SQLite, so the tests run without a C toolchain.
//
// github.com/mattn/go-sqlite3 requires cgo. Without it the package still
// compiles but every driver call is a stub that returns
// "Binary was compiled with 'CGO_ENABLED=0'", so every test that opens a
// database fails. That is not a hypothetical: internal/clients, internal/oidc
// and internal/recovery could not run at all on a machine without a C
// compiler, and CI never noticed because it only ran ./internal/attributes/...
//
// Production is unaffected. The Dockerfile builds with CGO_ENABLED=1, so the
// image ships mattn/go-sqlite3 exactly as before; this file is compiled only
// when cgo is off, which is tests and local development.
package store

import (
	"database/sql"

	sqlite "modernc.org/sqlite"
)

const driverName = "sqlite3"

// PureGoDriver reports whether the database is running on the cgo-free driver.
const PureGoDriver = true

// Registered under the name the rest of the package already uses, so sql.Open
// is identical in both builds. Safe because the two driver files are mutually
// exclusive: exactly one is ever compiled in, so this can never collide with
// mattn's own registration.
func init() {
	sql.Register(driverName, &sqlite.Driver{})
}
