// Package web embeds the static dashboard assets so they can be served
// directly from the LIAS binary without external file dependencies.
// This file exists specifically to resolve the relative path limitations
// of the //go:embed directive when main.go is in a cmd/ subdirectory.
//
// File:    apps/lias/web/embed.go
// Version: 1.0
package web

import (
    "embed"
    "io/fs"
)

//go:embed index.html src
var content embed.FS

// FS returns a sub-filesystem containing the embedded web assets,
// allowing the HTTP server to serve them cleanly.
func FS() fs.FS {
    sub, err := fs.Sub(content, ".")
    if err != nil {
        // This panic should only occur if the embed directive fails at compile time,
        // which means the binary is fundamentally broken.
        panic(err)
    }
    return sub
}
