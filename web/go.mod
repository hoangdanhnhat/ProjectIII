// Module boundary for the front-end workspace. There is no Go code under
// web/; this file only stops `go build ./...` from descending into
// web/node_modules.
module example.com/dfir-collector/web

go 1.24
