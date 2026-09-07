// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build cgo

package store

// The production driver. The Dockerfile builds with CGO_ENABLED=1, so this is
// what ships and what the IdP has always used.
import _ "github.com/mattn/go-sqlite3"

// driverName is what sql.Open is given. Both builds register under the same
// name so nothing outside this file needs to know which driver is present.
const driverName = "sqlite3"

// PureGoDriver reports whether the database is running on the cgo-free driver.
// Only tests care, and only to say so if something ever diverges.
const PureGoDriver = false
