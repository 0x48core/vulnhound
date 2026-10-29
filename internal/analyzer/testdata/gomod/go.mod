module example.com/app

go 1.22

require (
	github.com/gin-gonic/gin v1.9.0
	golang.org/x/net v0.17.0 // indirect
	example.com/local v0.0.0
	example.com/old v1.0.0
)

replace example.com/local => ../local

replace example.com/old v1.0.0 => example.com/new v1.2.0
