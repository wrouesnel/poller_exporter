// Code generated by go-bindata.
// sources:
// web/static/css/bootstrap-theme.css
// web/static/css/bootstrap.css
// web/static/fonts/glyphicons-halflings-regular.eot
// web/static/fonts/glyphicons-halflings-regular.svg
// web/static/fonts/glyphicons-halflings-regular.ttf
// web/static/fonts/glyphicons-halflings-regular.woff
// web/static/fonts/glyphicons-halflings-regular.woff2
// web/static/js/bootstrap.js
// web/templates/index.amber
// web/templates/status.html
// DO NOT EDIT!

package main

import (
	"net/http"
	"fmt"
	"io/ioutil"
	"strings"
	"os"
	"path/filepath"
)

// bindataRead reads the given file from disk. It returns an error on failure.
func bindataRead(path, name string) ([]byte, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("Error reading asset %s at %s: %v", name, path, err)
	}
	return buf, err
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

// staticCssBootstrapThemeCss reads file data from disk. It returns an error on failure.
func staticCssBootstrapThemeCss() (*asset, error) {
	path := filepath.Join(rootDir, "static/css/bootstrap-theme.css")
	name := "static/css/bootstrap-theme.css"
	bytes, err := bindataRead(path, name)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("Error reading asset info %s at %s: %v", name, path, err)
	}

	a := &asset{bytes: bytes, info: fi}
	return a, err
}

// staticCssBootstrapCss reads file data from disk. It returns an error on failure.
func staticCssBootstrapCss() (*asset, error) {
	path := filepath.Join(rootDir, "static/css/bootstrap.css")
	name := "static/css/bootstrap.css"
	bytes, err := bindataRead(path, name)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("Error reading asset info %s at %s: %v", name, path, err)
	}

	a := &asset{bytes: bytes, info: fi}
	return a, err
}

// staticFontsGlyphiconsHalflingsRegularEot reads file data from disk. It returns an error on failure.
func staticFontsGlyphiconsHalflingsRegularEot() (*asset, error) {
	path := filepath.Join(rootDir, "static/fonts/glyphicons-halflings-regular.eot")
	name := "static/fonts/glyphicons-halflings-regular.eot"
	bytes, err := bindataRead(path, name)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("Error reading asset info %s at %s: %v", name, path, err)
	}

	a := &asset{bytes: bytes, info: fi}
	return a, err
}

// staticFontsGlyphiconsHalflingsRegularSvg reads file data from disk. It returns an error on failure.
func staticFontsGlyphiconsHalflingsRegularSvg() (*asset, error) {
	path := filepath.Join(rootDir, "static/fonts/glyphicons-halflings-regular.svg")
	name := "static/fonts/glyphicons-halflings-regular.svg"
	bytes, err := bindataRead(path, name)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("Error reading asset info %s at %s: %v", name, path, err)
	}

	a := &asset{bytes: bytes, info: fi}
	return a, err
}

// staticFontsGlyphiconsHalflingsRegularTtf reads file data from disk. It returns an error on failure.
func staticFontsGlyphiconsHalflingsRegularTtf() (*asset, error) {
	path := filepath.Join(rootDir, "static/fonts/glyphicons-halflings-regular.ttf")
	name := "static/fonts/glyphicons-halflings-regular.ttf"
	bytes, err := bindataRead(path, name)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("Error reading asset info %s at %s: %v", name, path, err)
	}

	a := &asset{bytes: bytes, info: fi}
	return a, err
}

// staticFontsGlyphiconsHalflingsRegularWoff reads file data from disk. It returns an error on failure.
func staticFontsGlyphiconsHalflingsRegularWoff() (*asset, error) {
	path := filepath.Join(rootDir, "static/fonts/glyphicons-halflings-regular.woff")
	name := "static/fonts/glyphicons-halflings-regular.woff"
	bytes, err := bindataRead(path, name)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("Error reading asset info %s at %s: %v", name, path, err)
	}

	a := &asset{bytes: bytes, info: fi}
	return a, err
}

// staticFontsGlyphiconsHalflingsRegularWoff2 reads file data from disk. It returns an error on failure.
func staticFontsGlyphiconsHalflingsRegularWoff2() (*asset, error) {
	path := filepath.Join(rootDir, "static/fonts/glyphicons-halflings-regular.woff2")
	name := "static/fonts/glyphicons-halflings-regular.woff2"
	bytes, err := bindataRead(path, name)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("Error reading asset info %s at %s: %v", name, path, err)
	}

	a := &asset{bytes: bytes, info: fi}
	return a, err
}

// staticJsBootstrapJs reads file data from disk. It returns an error on failure.
func staticJsBootstrapJs() (*asset, error) {
	path := filepath.Join(rootDir, "static/js/bootstrap.js")
	name := "static/js/bootstrap.js"
	bytes, err := bindataRead(path, name)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("Error reading asset info %s at %s: %v", name, path, err)
	}

	a := &asset{bytes: bytes, info: fi}
	return a, err
}

// templatesIndexAmber reads file data from disk. It returns an error on failure.
func templatesIndexAmber() (*asset, error) {
	path := filepath.Join(rootDir, "templates/index.amber")
	name := "templates/index.amber"
	bytes, err := bindataRead(path, name)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("Error reading asset info %s at %s: %v", name, path, err)
	}

	a := &asset{bytes: bytes, info: fi}
	return a, err
}

// templatesStatusHtml reads file data from disk. It returns an error on failure.
func templatesStatusHtml() (*asset, error) {
	path := filepath.Join(rootDir, "templates/status.html")
	name := "templates/status.html"
	bytes, err := bindataRead(path, name)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("Error reading asset info %s at %s: %v", name, path, err)
	}

	a := &asset{bytes: bytes, info: fi}
	return a, err
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if (err != nil) {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"static/css/bootstrap-theme.css": staticCssBootstrapThemeCss,
	"static/css/bootstrap.css": staticCssBootstrapCss,
	"static/fonts/glyphicons-halflings-regular.eot": staticFontsGlyphiconsHalflingsRegularEot,
	"static/fonts/glyphicons-halflings-regular.svg": staticFontsGlyphiconsHalflingsRegularSvg,
	"static/fonts/glyphicons-halflings-regular.ttf": staticFontsGlyphiconsHalflingsRegularTtf,
	"static/fonts/glyphicons-halflings-regular.woff": staticFontsGlyphiconsHalflingsRegularWoff,
	"static/fonts/glyphicons-halflings-regular.woff2": staticFontsGlyphiconsHalflingsRegularWoff2,
	"static/js/bootstrap.js": staticJsBootstrapJs,
	"templates/index.amber": templatesIndexAmber,
	"templates/status.html": templatesStatusHtml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func func() (*asset, error)
	Children map[string]*bintree
}
var _bintree = &bintree{nil, map[string]*bintree{
	"static": &bintree{nil, map[string]*bintree{
		"css": &bintree{nil, map[string]*bintree{
			"bootstrap-theme.css": &bintree{staticCssBootstrapThemeCss, map[string]*bintree{
			}},
			"bootstrap.css": &bintree{staticCssBootstrapCss, map[string]*bintree{
			}},
		}},
		"fonts": &bintree{nil, map[string]*bintree{
			"glyphicons-halflings-regular.eot": &bintree{staticFontsGlyphiconsHalflingsRegularEot, map[string]*bintree{
			}},
			"glyphicons-halflings-regular.svg": &bintree{staticFontsGlyphiconsHalflingsRegularSvg, map[string]*bintree{
			}},
			"glyphicons-halflings-regular.ttf": &bintree{staticFontsGlyphiconsHalflingsRegularTtf, map[string]*bintree{
			}},
			"glyphicons-halflings-regular.woff": &bintree{staticFontsGlyphiconsHalflingsRegularWoff, map[string]*bintree{
			}},
			"glyphicons-halflings-regular.woff2": &bintree{staticFontsGlyphiconsHalflingsRegularWoff2, map[string]*bintree{
			}},
		}},
		"js": &bintree{nil, map[string]*bintree{
			"bootstrap.js": &bintree{staticJsBootstrapJs, map[string]*bintree{
			}},
		}},
	}},
	"templates": &bintree{nil, map[string]*bintree{
		"index.amber": &bintree{templatesIndexAmber, map[string]*bintree{
		}},
		"status.html": &bintree{templatesStatusHtml, map[string]*bintree{
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
        data, err := Asset(name)
        if err != nil {
                return err
        }
        info, err := AssetInfo(name)
        if err != nil {
                return err
        }
        err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
        if err != nil {
                return err
        }
        err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
        if err != nil {
                return err
        }
        err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
        if err != nil {
                return err
        }
        return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
        children, err := AssetDir(name)
        // File
        if err != nil {
                return RestoreAsset(dir, name)
        }
        // Dir
        for _, child := range children {
                err = RestoreAssets(dir, filepath.Join(name, child))
                if err != nil {
                        return err
                }
        }
        return nil
}

func _filePath(dir, name string) string {
        cannonicalName := strings.Replace(name, "\\", "/", -1)
        return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}


func assetFS() http.FileSystem {
	for k := range _bintree.Children {
		return http.Dir(k)
	}
	panic("unreachable")
}
