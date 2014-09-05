// Package watcher implements filesystem notification,.
// Original work from https://godoc.org/github.com/mgutz/gosu/watcher

/*
FAQ:
How many files can be watched at once?

There are OS-specific limits as to how many watches can be created:

Linux: /proc/sys/fs/inotify/max_user_watches contains the limit, reaching this limit results in a
"no space left on device" error.
BSD / OSX: sysctl variables "kern.maxfiles" and "kern.maxfilesperproc", reaching these limits
results in a "too many open files" error.
*/

package fswatcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wheelcomplex/fsnotify"
	"github.com/wheelcomplex/misc"
)

const (
	// IgnoreThresholdRange is the amount of time in ns to ignore when
	// receiving watch events for the same file+same event
	IgnoreThresholdRange = 50 * 1000000 // convert to ms
)

// FileEvent is a wrapper around code.google.com/p/go.exp/fsnotify
// https://godoc.org/code.google.com/p/go.exp/fsnotify
type FileEvent struct {
	Event    *fsnotify.FileEvent
	Name     string
	UnixNano int64
}

func newFileEvent(originEvent *fsnotify.FileEvent, unixNano int64) *FileEvent {
	//log.Printf("to channel %+v\n", originEvent)
	return &FileEvent{Event: originEvent, Name: originEvent.Name, UnixNano: unixNano}
}

// Watcher is a wrapper around which adds some additional features:
//
// - recursive directory watch
// - buffer to even chan
// - even time
//
// Original work from https://github.com/bronze1man/kmg
type Watcher struct {
	Event chan *FileEvent
	Error chan error
	//default ignore all file start with "."
	IsIgnorePath func(path string) bool
	//default is nil,if is nil ,error send through Error chan,if is not nil,error handle by this func
	ErrorHandler func(path string, err error)
	isClosed     bool
	quit         chan bool
	threshold    int64 // Throughput Limitations
	pWatcher     *fsnotify.Watcher
	rWatcher     *fsnotify.Watcher
	scanLock     *sync.Mutex   // scan lock
	scanDone     chan struct{} // close when scan done
}

// NewWatcher creates an instance of watcher.
func NewWatcher(bufferSize int) (watcher *Watcher, err error) {
	originp, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	originr, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	watcher = &Watcher{
		pWatcher:     originp,
		rWatcher:     originr,
		Error:        make(chan error, 10),
		Event:        make(chan *FileEvent, bufferSize),
		IsIgnorePath: DefaultIsIgnorePath,
		threshold:    IgnoreThresholdRange,
		scanLock:     &sync.Mutex{},
		scanDone:     make(chan struct{}, 1),
	}
	go watcher.eventHandle()
	return
}

// Close closes the watcher channels.
func (w *Watcher) Close() error {
	if w.isClosed {
		return nil
	}
	perr := w.pWatcher.Close()
	rerr := w.rWatcher.Close()
	select {
	case <-w.scanDone:
		// already closed
	default:
		close(w.scanDone)
	}
	w.quit <- true
	w.isClosed = true
	if perr != nil || rerr != nil {
		return fmt.Errorf("%s, %s", perr.Error(), rerr.Error())
	}
	return nil
}

// Close closes the watcher channels.
func (w *Watcher) SetThreshold(l int64) int64 {
	old := w.threshold / 100000
	// min 1000000ns, 1ms
	if l < 1 {
		return old
	}
	w.threshold = l * 100000
	return old
}

//
type cacheInfo struct {
	last time.Time               // last active of this file
	list map[string]*os.FileInfo // index by event.String()
}

func newCacheInfo() *cacheInfo {
	cache := new(cacheInfo)
	cache.last = time.Now()
	cache.list = make(map[string]*os.FileInfo)
	return cache
}

// clean idle cache every 1 second, max idle 10 seconds
// clean all cache item on exit
func cacheCleaner(cache map[string]*cacheInfo, mu *sync.Mutex, exit chan struct{}) {
	tk := time.NewTicker(1e9) // one second tick
	var ts time.Time
	for {
		mu.Lock()
		ts = time.Now()
		for name, _ := range cache {
			if ts.Sub(cache[name].last) > 10e9 {
				// debug
				fmt.Printf("clean idle %v(%v)\n", name, ts.Sub(cache[name].last))
				delete(cache, name)
			}
		}
		mu.Unlock()
		select {
		case <-exit:
			fmt.Printf("cleaner exit\n")
			mu.Lock()
			for name, _ := range cache {
				fmt.Printf("clean all %v\n", name)
				delete(cache, name)
			}
			mu.Unlock()
			return
		case <-tk.C:
		}
	}
}

func (w *Watcher) eventProc(event *fsnotify.FileEvent, recursive bool, cache map[string]*cacheInfo, mu *sync.Mutex) {
	//fmt.Printf("recursive(%v) event %+v\n", recursive, event)
	if w.IsIgnorePath(event.Name) {
		return
	}
	// you can not stat a delete file...
	if event.IsDelete() {
		// remove deleted event cache
		mu.Lock()
		if _, ok := cache[event.Name]; ok {
			delete(cache, event.Name)
		}
		mu.Unlock()
		// adjust with arbitrary value because it was deleted
		// before it got here
		w.Event <- newFileEvent(event, time.Now().UnixNano()-10)
		return
	}

	fi, err := os.Stat(event.Name)
	if os.IsNotExist(err) {
		//fmt.Println("not exists", event)
		return
	}

	// fsnotify is sending multiple MODIFY events for the same
	// file which is likely OS related. The solution here is to
	// compare the current stats of a file against its last stats
	// (if any) and if it falls within a nanoseconds threshold,
	// ignore it.
	mu.Lock()
	if _, ok := cache[event.Name]; !ok {
		cache[event.Name] = newCacheInfo()
	}
	evTag := event.String() // filename+event
	oldFI := cache[event.Name].list[evTag]
	cache[event.Name].list[evTag] = &fi
	cache[event.Name].last = time.Now()
	mu.Unlock()

	if oldFI != nil && fi.ModTime().UnixNano() < (*oldFI).ModTime().UnixNano()+w.threshold {
		//fmt.Printf("threshold(%v) inside %v\n", w.threshold, (*oldFI).ModTime().UnixNano()+w.threshold-fi.ModTime().UnixNano())
		return
	}

	fmt.Println("sending fi", fi.ModTime().UnixNano()/1000000, event.Name)
	w.Event <- newFileEvent(event, fi.ModTime().UnixNano())

	if err != nil {
		//rename send two events,one old file,one new file,here ignore old one
		if os.IsNotExist(err) {
			return
		}
		w.errorHandle(event.Name, err)
		return
	}
	if fi.IsDir() && recursive {
		w.WatchRecursive(event.Name)
	}
	return
}

func (w *Watcher) eventHandle() {
	// waiting for first watch scan done
	<-w.scanDone
	fmt.Printf("first scan done, start to read event.\n")

	cache := make(map[string]*cacheInfo) // cache index by event.Name
	mu := &sync.Mutex{}
	cleanExit := make(chan struct{})
	go cacheCleaner(cache, mu, cleanExit)
	defer func() {
		cleanExit <- struct{}{}
	}()

	var event *fsnotify.FileEvent
	var err error
	for {
		select {
		case event = <-w.pWatcher.Event:
			w.eventProc(event, false, cache, mu)
		case event = <-w.rWatcher.Event:
			w.eventProc(event, true, cache, mu)
		case err = <-w.pWatcher.Error:
			w.errorHandle(event.Name, err)
		case err = <-w.rWatcher.Error:
			w.errorHandle(event.Name, err)
		case <-w.quit:
			break
		}
	}
}
func (w *Watcher) errorHandle(path string, err error) {
	if w.ErrorHandler == nil {
		w.Error <- err
		return
	}
	w.ErrorHandler(path, err)
}

// GetErrorChan gets error chan.
func (w *Watcher) GetErrorChan() chan error {
	return w.Error
}

// GetEventChan gets event chan.
func (w *Watcher) GetEventChan() chan *FileEvent {
	return w.Event
}

// watch watches a directory recursively. If a dir is created
// within directory and recursive is true it is also watched.
func (w *Watcher) watch(path string, recursive bool) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if recursive {
		folders, err := w.getSubFolders(path)
		if err != nil {
			return err
		}
		if len(folders) == 0 {
			fmt.Printf("recursive add watch %s end.\n", path)
			return nil
		}
		for _, v := range folders {
			if v == path {
				err = w.rWatcher.Watch(path)
				if err != nil {
					return err
				}
				fmt.Printf("add watch by recursive: %v\n", path)
			} else {
				err = w.watch(v, true)
				if err != nil {
					return err
				}
			}
		}
	} else {
		err = w.pWatcher.Watch(path)
		if err != nil {
			return err
		}
		fmt.Printf("add watch: %v\n", path)
	}
	return nil
}

// WatchRecursive watches a directory recursively. If a dir is created
// within directory it is also watched.
func (w *Watcher) WatchRecursive(path string) error {
	// waiting for another scan done
	fmt.Printf("recursively scan: %s\n", path)
	w.scanLock.Lock()
	defer w.scanLock.Unlock()
	select {
	case <-w.scanDone:
		// already closed, re-create
		w.scanDone = make(chan struct{}, 1)
	default:
	}
	err := w.watch(path, true)
	select {
	case <-w.scanDone:
		// already closed
	default:
		close(w.scanDone)
	}
	fmt.Printf("recursively scan done: %s\n", path)
	return err
}

// Watch watches a directory, do not include sub-dir
func (w *Watcher) Watch(path string) error {
	// waiting for another scan done
	fmt.Printf("scan: %s\n", path)
	w.scanLock.Lock()
	defer w.scanLock.Unlock()
	select {
	case <-w.scanDone:
		// already closed, re-create
		w.scanDone = make(chan struct{}, 1)
	default:
	}
	err := w.watch(path, false)
	select {
	case <-w.scanDone:
		// already closed
	default:
		close(w.scanDone)
	}
	fmt.Printf("scan done: %s\n", path)
	return err
}

func (w *Watcher) getSubFolders(path string) (paths []string, err error) {
	err = filepath.Walk(path, func(newPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return nil
		}
		if w.IsIgnorePath(newPath) {
			return filepath.SkipDir
		}
		paths = append(paths, newPath)
		return nil
	})
	return paths, err
}

// DefaultIsIgnorePath checks whether a path is ignored. Currently defaults
// to hidden files on *nix systems, ie they start with a ".".
func DefaultIsIgnorePath(path string) bool {
	return isDotFile(path) || isVimFile(path)
}

func isDotFile(path string) bool {
	if path == "./" {
		return false
	}
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") {
		return true
	}
	return false
}

func isVimFile(path string) bool {
	base := filepath.Base(path)
	return misc.IsNumeric(base)
}
