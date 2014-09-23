// Package fswatcher implements filesystem notification,.
// Original work from https://godoc.org/github.com/mgutz/gosu/watcher

/*
FAQ:
How many files can be watched at once?

There are OS-specific limits as to how many watches can be created:

Linux: /proc/sys/fs/inotify/max_user_watches contains the limit, reaching this limit results in a
"no space left on device" error.
BSD / OSX: sysctl variables "kern.maxfiles" and "kern.maxfilesperproc", reaching these limits
results in a "too many open files" error.

epoll_wait: interrupted system call 0}
*/

package fswatcher

import (
	"fmt"
	"hash"
	"hash/fnv"
	"os"
	"path/filepath"
	"regexp"
	//rd "runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	fc "github.com/wheelcomplex/folderscanner"
	"github.com/wheelcomplex/fsnotify"
	"github.com/wheelcomplex/goqueue/stack"
)

// HashWatcher use fnv1a hash to map(mod) path to watcher
// and provide output channel for read events
type HashWatcher struct {
	Events   chan fsnotify.Event          // event output channel, read all Stack.Out() and forward here
	Errors   chan error                   // error output channel
	watchers map[uint64]*fsnotify.Watcher // working watcher, output channel == Stack.RawIn()
	size     int                          // number of watcher
	closed   bool                         // flag
	exited   chan struct{}                // flag
	closing  chan struct{}                // notify for forwarder
	hasher   hash.Hash64                  //
	hashMu   sync.Mutex                   // lock
	closeMu  sync.Mutex                   // lock
}

// NewHashWatcher return HashWatcher with size fsnotify.Watcher
// size less then 5 will got 5 Watcher
func NewHashWatcher(size int) (*HashWatcher, error) {
	if size < 1 {
		size = 1
	}
	self := &HashWatcher{
		Events:   make(chan fsnotify.Event, 1024*size),
		Errors:   make(chan error, 1024*size),
		watchers: make(map[uint64]*fsnotify.Watcher),
		size:     size,
		closed:   false,
		closing:  make(chan struct{}, size),
		exited:   make(chan struct{}, size),
		hasher:   fnv.New64a(),
		hashMu:   sync.Mutex{},
		closeMu:  sync.Mutex{},
	}
	var err error
	for i := 0; i < size; i++ {
		self.watchers[uint64(i)], err = fsnotify.NewWatcher(1024)
		if err != nil {
			return nil, err
		}
		//fmt.Printf("HashWatcher NewWatcher %d/%d\n", size, i)
		// goroutine to forward events to output
		go self.evReciver(uint64(i))
		go self.erReciver(uint64(i))
	}
	return self, nil
}

// Close close all watchers/stacks/channel
func (self *HashWatcher) Close() {
	self.closeMu.Lock()
	defer self.closeMu.Unlock()
	if self.closed {
		return
	}
	self.closed = true
	//fmt.Printf("HashWatcher %p closing ...\n", self)
	// close all watcher so forwarder exit
	for i, _ := range self.watchers {
		self.watchers[i].Close()
	}
	// waiting for Reciver exist
	for _ = range self.watchers {
		<-self.exited //evReciver
		<-self.exited //erReciver
	}
	//
	//fmt.Printf("HashWatcher %p closed\n", self)
	return
}

// evReciver forward event to stack
func (self *HashWatcher) evReciver(id uint64) {
	//fmt.Printf("evReciver %d running\n", id)
	defer func() {
		//fmt.Printf("evReciver %d closing ...\n", id)
		self.exited <- struct{}{}
		//fmt.Printf("evReciver %d closed\n", id)
	}()
	for event := range self.watchers[id].Events {
		self.Events <- event
	}
	return
}

// erReciver forward error to stack
func (self *HashWatcher) erReciver(id uint64) {
	//fmt.Printf("erReciver %d running\n", id)
	defer func() {
		//fmt.Printf("erReciver %d closing ...\n", id)
		self.exited <- struct{}{}
		//fmt.Printf("erReciver %d closed\n", id)
	}()
	for err := range self.watchers[id].Errors {
		self.Errors <- err
	}
	return
}

// IsWatched return true if path already watched
func (self *HashWatcher) IsWatched(path string) bool {
	i := self.Sum64a(path) % uint64(self.size)
	return self.watchers[i].IsWatched(path)
}

// AddPath map and watch path
func (self *HashWatcher) Add(path string) error {
	i := self.Sum64a(path) % uint64(self.size)
	if self.watchers[i].IsWatched(path) {
		return nil
	}
	err := self.watchers[i].Add(path)
	//fmt.Printf("AddPath %s to slot %d: %v\n", path, i, err)
	return err
}

// RemovePath map and remove path from watcher
func (self *HashWatcher) Remove(path string) error {
	i := self.Sum64a(path) % uint64(self.size)
	err := self.watchers[i].Remove(path)
	//fmt.Printf("RemovePath %s from slot %d: %v\n", path, i, err)
	return err
}

// Sum64a
func (self *HashWatcher) Sum64a(data string) uint64 {
	self.hashMu.Lock()
	defer self.hashMu.Unlock()
	self.hasher.Reset()
	self.hasher.Write([]byte(data))
	return self.hasher.Sum64()
}

// Count return watched path size
func (self *HashWatcher) Count() uint64 {
	var pathNum uint64
	for i, _ := range self.watchers {
		pathNum = pathNum + uint64(self.watchers[i].Count())
	}
	return pathNum
}

/////////////////////////////////////

const (
	// IgnoreThresholdRange is the amount of time in ns to ignore when
	// receiving watch events for the same file+same event
	IgnoreThresholdRange = 1e5
)

var DUMMY_EVENT fsnotify.Event

func init() {
	DUMMY_EVENT = fsnotify.NewEvent(fsnotify.Create|fsnotify.Write, "/dev/null")
}

const (
	STAGE_INIT int = iota // 0
	STAGE_WATCH
	STAGE_LAZY
)

// ActEvent watcher output event
type ActEvent struct {
	Stage    int            // event from which stage, STAGE_INIT or STAGE_WATCH
	Event    fsnotify.Event // underdelay event, exported
	IsFolder bool           // is this a directory?
	UnixNano int64          // mtime of the file
	Inode    uint64         // inode number of the file
	Err      error
	Id       uint64 // fnv64a hash of name
}

// convert fsnotify.Event to *ActEvent with mtime and error
func newActEvent(stage int, id uint64, originEvent fsnotify.Event, unixNano int64, inode uint64, folder bool, err error) *ActEvent {
	//log.Printf("to channel %+v\n", originEvent)
	e := &ActEvent{
		Stage:    stage,
		Event:    originEvent,
		IsFolder: folder,
		UnixNano: unixNano,
		Inode:    inode,
		Err:      err,
		Id:       id,
	}
	return e
}

// event cache
type cacheInfo struct {
	last time.Time               // last active of this file
	list map[uint32]*os.FileInfo // index by event.Mask()
}

// newCacheInfo return new *cacheInfo
func newCacheInfo() *cacheInfo {
	info := new(cacheInfo)
	info.last = time.Now()
	info.list = make(map[uint32]*os.FileInfo)
	return info
}

// PathWatcher is a wrapper around which adds some additional features:
//
// output channel will closed after *PathWatcher.Close()
type PathWatcher struct {
	events        *stack.Stack              // output stack
	eventsIn      chan<- interface{}        // In() of output stack
	pWatcher      *HashWatcher              // group of watcher
	rWatcher      *HashWatcher              // group of watcher
	cache         map[uint64]*cacheInfo     // event cache, index by FileInfo.Inode
	cacheMu       *sync.Mutex               // lock
	watcherNum    int                       // output channel buffer size
	isClosed      bool                      // is watcher is working
	closing       chan struct{}             // tell eventProc to closing
	exited        chan struct{}             // eventProc exited
	threshold     int64                     // Throughput Limitations
	maxCacheIdle  time.Duration             //
	watchIncRegex map[string]*regexp.Regexp // compiled watchInclude filter
	watchExcRegex map[string]*regexp.Regexp // compiled watchExclude filter
	scanDone      chan error                // scan result
	scanMu        *sync.Mutex               // lock
	miscMutex     *sync.Mutex               // lock
	lazyAddCh     chan<- interface{}        // recursive watch new dir
	addStack      *stack.Stack              // add watch queue
	removeWatch   chan<- interface{}        // remove watch deleted dir
	removeStack   *stack.Stack              // remove watch queue
	hasher        hash.Hash64               // string to uint hasher
	goCount       int                       // goroutine counter
	rootList      map[string]struct{}       // root dir
}

// NewPathWatcher creates an instance of PathWatcher.
func NewPathWatcher(size int) *PathWatcher {
	if size < 1 {
		size = 1
	}
	self := &PathWatcher{
		watcherNum:    size,
		threshold:     IgnoreThresholdRange,
		maxCacheIdle:  5e9, // 5 seconds
		watchIncRegex: make(map[string]*regexp.Regexp),
		watchExcRegex: make(map[string]*regexp.Regexp),
		scanDone:      make(chan error, 1),
		isClosed:      true,
		closing:       make(chan struct{}, 8),
		exited:        make(chan struct{}, 8),
		cacheMu:       &sync.Mutex{},
		scanMu:        &sync.Mutex{},
		miscMutex:     &sync.Mutex{},
		hasher:        fnv.New64a(),
		goCount:       0,
	}
	return self
}

// Stat return cache size, stack size
func (self *PathWatcher) Sum64a(data string) uint64 {
	self.miscMutex.Lock()
	defer self.miscMutex.Unlock()
	self.hasher.Reset()
	self.hasher.Write([]byte(data))
	return self.hasher.Sum64()
}

// Stat
func (self *PathWatcher) Stat() (uint64, uint64, uint64, uint64) {
	if self.isClosed {
		return 0, 0, 0, 0
	}
	return uint64(self.pWatcher.Count() + self.rWatcher.Count()), uint64(len(self.cache)), self.addStack.GetCacheSize(), self.removeStack.GetCacheSize()
}

func (self *PathWatcher) newWatchHandle() error {
	var err error
	self.miscMutex.Lock()
	defer self.miscMutex.Unlock()
	if self.isClosed == false {
		// no closed, do not need re-initial
		return nil
	}
	self.rootList = make(map[string]struct{})
	//
	self.isClosed = false
	self.cache = make(map[uint64]*cacheInfo)
	self.pWatcher, err = NewHashWatcher(self.watcherNum)
	if err != nil {
		return err
	}
	self.rWatcher, err = NewHashWatcher(self.watcherNum)
	if err != nil {
		return err
	}
	self.events = stack.NewStack(256, -1, false)
	self.eventsIn = self.events.In()
	self.addStack = stack.NewStack(256, -1, false)
	self.lazyAddCh = self.addStack.In()
	self.removeStack = stack.NewStack(256, -1, false)
	self.removeWatch = self.removeStack.In()

	self.scanDone = make(chan error, 8)
	//
	self.goCount = 0
	//
	go self.cacheMgr()
	self.goCount++
	//
	go self.watchMgr(1)
	self.goCount++
	//go self.watchMgr(2)
	//self.goCount++
	//go self.watchMgr(3)
	//self.goCount++
	//go self.watchMgr(3)
	//self.goCount++
	//
	go self.eventProc(false)
	go self.eventProc(false)
	//
	go self.eventProc(true)
	go self.eventProc(true)
	go self.eventProc(true)
	go self.eventProc(true)
	go self.eventProc(true)
	go self.eventProc(true)
	//
	go self.errorRead(false)
	self.goCount++
	go self.errorRead(true)
	self.goCount++
	//
	return nil
}

// Close closes the watcher channels.
func (self *PathWatcher) Close() error {
	self.miscMutex.Lock()
	defer self.miscMutex.Unlock()
	if self.isClosed {
		return nil
	}
	//fmt.Printf("PathWatcher %p closing ...\n", self)
	self.isClosed = true
	// abort running scan
	select {
	case <-self.scanDone:
		// already closed
	default:
		close(self.scanDone)
	}
	// waiting for scan exit
	self.scanMu.Lock()
	defer self.scanMu.Unlock()
	//
	// close underdelay watcher, triger eventRead exit
	self.pWatcher.Close()
	self.rWatcher.Close()
	//
	// eventProc + cacheMgr + watchMgr
	for i := 0; i < self.goCount; i++ {
		self.closing <- struct{}{}
		//println("self.closing <-")
	}
	// waiting for event handle + cacheMgr + watchMgr exit
	for i := 0; i < self.goCount; i++ {
		<-self.exited
		//println("<-self.exited")
	}
	//
	// close stack
	self.addStack.Close()
	self.removeStack.Close()
	//
	self.events.Close()
	//
	self.cache = nil
	//
	fmt.Printf("PathWatcher %p closed\n", self)
	return nil
}

// errorRead running in goroutine and forward error event to output
func (self *PathWatcher) errorRead(recursive bool) {
	//fmt.Printf("errorRead(%v) running ...\n", recursive)
	var everror error
	var watcher *HashWatcher
	if recursive {
		watcher = self.rWatcher
	} else {
		watcher = self.pWatcher
	}
	// fast read event, if event pending in epoll_wait will case event lost
	for {
		select {
		case <-self.closing:
			//fmt.Printf("errorRead(%v) closing ...\n", recursive)
			self.exited <- struct{}{}
			//fmt.Printf("errorRead(%v) closed.\n", recursive)
			return
		case everror = <-watcher.Errors:
			self.eventSend(newActEvent(STAGE_WATCH, 0, DUMMY_EVENT, 0, 0, false, everror), nil)
		}
	}
	return
}

// eventProc running in goroutine and forward event to output
func (self *PathWatcher) eventProc(recursive bool) {
	//fmt.Printf("eventProc(%v) running ...\n", recursive)
	var evInterface interface{}
	var event fsnotify.Event
	tk := time.NewTicker(5e9) // second tick
	defer tk.Stop()
	var watcher *HashWatcher
	if recursive {
		watcher = self.rWatcher
	} else {
		watcher = self.pWatcher
	}
	//
	for evInterface = range watcher.Events {
		event = evInterface.(fsnotify.Event)
		//
		//evcnt++
		//
		hid := self.Sum64a(event.Name)
		// you can not stat a delete file...
		if event.IsDelete() {
			self.removeWatch <- &idPath{id: hid, path: event.Name}
			//fmt.Printf("%d, removeWatch(%v) event %+v\n", hid, recursive, event)
			// adjust with arbitrary value because it was deleted
			// before it got here
			self.eventSend(newActEvent(STAGE_WATCH, hid, event, time.Now().UnixNano()-10, 0, false, nil), nil)
			continue
		}
		if self.watchMatch(event.Name) == false {
			// TODO: test match
			fmt.Printf("IgnorePath eventProc(%v) event %+v\n", recursive, event)
			continue
		}
		//fmt.Printf("%d, eventProc(%v) event %+v\n", hid, recursive, event)
		fi, err := os.Lstat(event.Name)
		//rename send two events,one old file,one new file,here ignore old one
		if os.IsNotExist(err) {
			continue
		}
		//if err != nil {
		//	// too many levels of symbolic links/fi=<nil>
		//	fmt.Printf("path exist but error: err=%v/fi=%v/event=%v\n", err, fi, event)
		//}
		if fi == nil {
			self.eventSend(newActEvent(STAGE_WATCH, hid, event, time.Now().UnixNano()-10, 0, false, nil), nil)
			continue
		}
		isDir := fi.IsDir()
		self.eventSend(newActEvent(STAGE_WATCH, hid, event, fi.ModTime().UnixNano(), fi.Sys().(*syscall.Stat_t).Ino, isDir, nil), fi)
		//
		// do not watch symbolic link
		//
		if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
			//fmt.Println("skipped symbolic link", event)
			continue
		}
		//
		if recursive && isDir && event.IsCreate() {
			// first watch, direct watch, no recursive
			// self.rWatcher
			err = watcher.Add(event.Name)
			if err != nil {
				self.eventSend(newActEvent(STAGE_WATCH, hid, event, fi.ModTime().UnixNano(), fi.Sys().(*syscall.Stat_t).Ino, isDir, err), fi)
			}
			// recursive scan
			self.lazyAddCh <- &idPath{id: hid, path: event.Name}
		} else {
			//fmt.Printf("%d, eventProc(%v), isDir %v, IsCreate %v, event %+v\n", hid, recursive, isDir, event.IsCreate(), event)
		}
		///////////////////////////
	}
	//fmt.Printf("eventProc(%v) closing ...\n", recursive)
	self.exited <- struct{}{}
	//fmt.Printf("eventProc(%v) closed.\n", recursive)
	return
}

//
func (self *PathWatcher) watchMgr(id int) {
	// signle thread, do not need lock
	addCh := self.addStack.Out()
	removeCh := self.removeStack.Out()
	tk := time.NewTicker(5e8) // 500ms
	defer tk.Stop()
	lazyList := make(map[string]struct{})
	//var preMiss int64 = -1
	for {
		select {
		case <-tk.C:
			if self.addStack.GetCacheSize() == 0 && len(self.cache) < 256 && len(lazyList) > 0 {
				//fmt.Printf("watchMgr#%d, lazy watch %d paths.\n", id, len(lazyList))
				for lazyPath, _ := range lazyList {
					//fmt.Printf("watchMgr, recursive watch lazyPath %v\n", lazyPath)
					self.lazyWatch(lazyPath)
					delete(lazyList, lazyPath)
				}
			}
		case addInfo := <-addCh:
			// have to re-scan parent dir for missed events
			lazyList[filepath.Dir(addInfo.(*idPath).path)] = struct{}{}
			//
			lazyList[addInfo.(*idPath).path] = struct{}{}
			//
		case removeInfo := <-removeCh:
			// BUG: inotify_rm_watch: invalid argument
			go func() {
				if self.pWatcher.IsWatched(removeInfo.(*idPath).path) {
					self.pWatcher.Remove(removeInfo.(*idPath).path)
				}
				if self.rWatcher.IsWatched(removeInfo.(*idPath).path) {
					self.rWatcher.Remove(removeInfo.(*idPath).path)
				}
			}()
		case <-self.closing:
			close(self.lazyAddCh)
			close(self.removeWatch)
			self.exited <- struct{}{}
			return
		}
	}
}

// eventSend O(n) func
//
func (self *PathWatcher) eventSend(ae *ActEvent, fi os.FileInfo) {
	if ae.Id == 0 {
		// only error
		self.eventsIn <- ae
		return
	}
	// fsnotify is sending multiple MODIFY events for the same
	// file which is likely OS related. The solution here is to
	// compare the current stats of a file against its last stats
	// (if any) and if it falls within a nanoseconds threshold,
	// ignore it.
	if self.threshold > 0 {
		self.cacheMu.Lock()
		defer self.cacheMu.Unlock()
		evTag := ae.Event.OpVar() // filename+event
		if _, ok := self.cache[ae.Id]; !ok {
			self.cache[ae.Id] = newCacheInfo()
		}
		oldFI, oldok := self.cache[ae.Id].list[evTag]
		tsnow := time.Now()
		if oldok {
			if fi != nil && oldFI != nil {
				if fi.ModTime().UnixNano() < (*oldFI).ModTime().UnixNano()+self.threshold {
					//fmt.Printf("SKKIPED, %d, threshold(%v) >= %v\n", evTag, self.threshold, ((*oldFI).ModTime().UnixNano()+self.threshold)-fi.ModTime().UnixNano())
					return
				}
			} else if fi == nil && oldFI != nil {
				if tsnow.UnixNano() < self.cache[ae.Id].last.UnixNano()+self.threshold {
					//fmt.Printf("SKKIPED, %d, delete/error threshold(%v) >= %v\n", evTag, self.threshold, (self.threshold+self.cache[ae.Id].last.UnixNano())-tsnow.UnixNano())
					return
				}
			}
		}
		self.cache[ae.Id].last = tsnow
		// fi may be <nil>
		self.cache[ae.Id].list[evTag] = &fi
	}
	self.eventsIn <- ae
	if ae.Stage == STAGE_LAZY {
		// recursive scan lazy path
		self.lazyAddCh <- &idPath{id: ae.Id, path: ae.Event.Name}
	}
	return

}

type idPath struct {
	id   uint64
	path string
}

//
func (self *PathWatcher) cacheMgr() {
	tk := time.NewTicker(3e9)
	defer func() {
		tk.Stop()
		//fmt.Printf("cacheMgr closing ...\n")
		self.exited <- struct{}{}
		//fmt.Printf("cacheMgr closed.\n")
	}()
	for {
		select {
		case <-self.closing:
			return
		case ts := <-tk.C:
			for name, _ := range self.cache {
				self.cacheMu.Lock()
				if ts.Sub(self.cache[name].last) > self.maxCacheIdle {
					// debug
					//fmt.Printf("clean idle %v(%v/%v)\n", name, ts.Sub(self.cache[name].last), self.maxCacheIdle)
					delete(self.cache, name)
				}
				self.cacheMu.Unlock()
			}
			//if len(self.cache) < 128 {
			//	rd.FreeOSMemory()
			//}
		}
	}
}

/*
// verify
func (self *PathWatcher) verify(path string) int64 {
	//
	var miss int64 = 0
	//
	folderScanner := fc.NewFolderScanner(self.watcherNum)
	for pattern, _ := range self.watchIncRegex {
		//fmt.Printf("add SetScanFilter: %v/%v\n", true, pattern)
		folderScanner.SetScanFilter(true, pattern)
	}
	for pattern, _ := range self.watchExcRegex {
		//fmt.Printf("add SetScanFilter: %v/%v\n", false, pattern)
		folderScanner.SetScanFilter(false, pattern)
	}
	dirOut, err := folderScanner.Scan(path, fc.FOLDER_SCAN_DIR_ONLY, true)
	//fmt.Printf("folderScanner.Scan: %v\n", err)
	if err != nil {
		return -1
	}
	defer func() {
		//fmt.Printf("return folderScanner closing: %v\n", path)
		folderScanner.Close()
		//fmt.Printf("return folderScanner closed: %v\n", path)
	}()
	for newDir := range dirOut {
		newInfo := newDir.(*fc.PathInfo)
		//fmt.Printf("recursive scan out: %v\n", newInfo.Path)
		err := newInfo.Err
		path := newInfo.Path
		if err != nil {
			continue
		}
		hid := self.Sum64a(path)
		if self.rWatcher.IsWatched(path) == false {
			fmt.Printf("MISS: %d || %s\n", hid, path)
			miss++
			//fmt.Printf("MISS: %d || %s\n", hid, path)
			err := self.rWatcher.Add(path)
			if err != nil {
				fmt.Printf("verify self.rWatcher.Add(%s): %v\n", path, err)
			}
		}
	}
	return miss
}
*/

// WatchRecursive watches a directory recursively. If a dir is created
// within directory it is also watched.
func (self *PathWatcher) WatchRecursive(path string, ignoreScanError bool) (<-chan interface{}, error) {
	// waiting for another scan done
	//fmt.Printf("Recursively Watch scan: %s\n", path)
	//self.scanMu.Lock()
	//defer self.scanMu.Unlock()
	select {
	case <-self.scanDone:
		// already closed, re-create
		self.scanDone = make(chan error, 8)
	default:
	}
	//
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	//
	if err := self.newWatchHandle(); err != nil {
		fmt.Printf("recursively newWatchHandle failed: %v\n", err)
		return nil, err
	}
	//
	self.rootList[path] = struct{}{}
	//
	//fmt.Printf("recursively newWatchHandle ok: %s\n", path)
	//
	if err := self.watch(STAGE_INIT, path, true, ignoreScanError); err != nil {
		//fmt.Printf("recursively scan failed: %v\n", err)
		return nil, err
	}
	//fmt.Printf("recursively scan ok: %s\n", path)
	return self.events.Out(), err
}

// Watch watches a directory, do not include sub-dir
func (self *PathWatcher) Watch(path string, ignoreScanError bool) (<-chan interface{}, error) {
	// waiting for another scan done
	//fmt.Printf("Watch scan: %s\n", path)
	//self.scanMu.Lock()
	//defer self.scanMu.Unlock()
	select {
	case <-self.scanDone:
		// already closed, re-create
		self.scanDone = make(chan error, 1)
	default:
	}
	//
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	//
	if err := self.newWatchHandle(); err != nil {
		fmt.Printf("scan newWatchHandle failed: %v\n", err)
		return nil, err
	}
	//
	if err := self.watch(STAGE_INIT, path, false, ignoreScanError); err != nil {
		fmt.Printf("scan failed: %v\n", err)
		return nil, err
	}
	//fmt.Printf("scan ok: %s\n", path)
	return self.events.Out(), err
}

//
func (self *PathWatcher) lazyWatch(path string) int64 {
	//
	var addCount int64
	dirs, _, _ := fc.ScanDir(path, fc.FOLDER_SCAN_DIR_ONLY, false)
	// dirs will not include path
	for key, _ := range dirs {
		// add to rWatcher
		if self.rWatcher.IsWatched(key) {
			continue
		}
		addCount++
		err := self.rWatcher.Add(key)
		self.eventSend(&ActEvent{
			Stage:    STAGE_LAZY,
			Event:    fsnotify.NewEvent(fsnotify.Create|fsnotify.Write, key),
			IsFolder: true,
			UnixNano: dirs[key].ModTime().UnixNano(),
			Inode:    dirs[key].Sys().(*syscall.Stat_t).Ino,
			Err:      err,
			Id:       self.Sum64a(key),
		}, dirs[key])
	}
	return addCount
}

func (self *PathWatcher) addPath(stage int, path string, fi os.FileInfo, recursive bool) error {
	var watcher *HashWatcher
	if recursive || stage == STAGE_LAZY {
		watcher = self.rWatcher
	} else {
		watcher = self.pWatcher
	}
	if watcher.IsWatched(path) {
		return nil
	}
	err := watcher.Add(path)
	//if err != nil {
	//	//fmt.Printf("recursive %v, addPath(%s): %v\n", recursive, path, err)
	//	return err
	//}
	self.eventSend(&ActEvent{
		Stage:    stage,
		Event:    fsnotify.NewEvent(fsnotify.Create|fsnotify.Write, path),
		IsFolder: true,
		UnixNano: fi.ModTime().UnixNano(),
		Inode:    fi.Sys().(*syscall.Stat_t).Ino,
		Err:      err,
		Id:       self.Sum64a(path),
	}, fi)
	return nil
}

// watch watches a directory, return path count and error
func (self *PathWatcher) watch(stage int, path string, recursive bool, ignoreScanError bool) error {
	//fmt.Printf("underdelay watch(%v): %v\n", recursive, path)
	//defer println("underdelay watch(%v): %v return\n", recursive, path)
	//
	fi, err := os.Lstat(path)
	//fmt.Println("root path", path, pathStat, err)
	if err != nil {
		return err
	}
	err = self.addPath(stage, path, fi, recursive)
	//fmt.Printf("underdelay addPath(%v): %v/%v\n", recursive, path, err)
	if err != nil {
		return err
	}
	if stage == STAGE_LAZY || recursive == false {
		return self.pWatch(stage, path, ignoreScanError)
	}
	return self.rWatch(stage, path, ignoreScanError)
}

//
func (self *PathWatcher) pWatch(stage int, path string, ignoreScanError bool) error {
	//
	dirs, _, errs := fc.ScanDir(path, fc.FOLDER_SCAN_DIR_ONLY, false)
	if len(errs) > 0 && ignoreScanError == false {
		var errstr string
		for key, _ := range errs {
			errstr = errstr + "//" + errs[key].Error()
		}
		return fmt.Errorf("pWatch %s: %s", path, errstr)
	}
	for key, _ := range dirs {
		err := self.addPath(stage, key, dirs[key], false)
		if err != nil {
			return err
		}
	}
	return nil
}

//
func (self *PathWatcher) rWatch(stage int, path string, ignoreScanError bool) error {
	//
	folderScanner := fc.NewFolderScanner(self.watcherNum)
	for pattern, _ := range self.watchIncRegex {
		//fmt.Printf("add SetScanFilter: %v/%v\n", true, pattern)
		folderScanner.SetScanFilter(true, pattern)
	}
	for pattern, _ := range self.watchExcRegex {
		//fmt.Printf("add SetScanFilter: %v/%v\n", false, pattern)
		folderScanner.SetScanFilter(false, pattern)
	}
	dirOut, err := folderScanner.Scan(path, fc.FOLDER_SCAN_DIR_ONLY, true)
	//fmt.Printf("folderScanner.Scan: %v\n", err)
	if err != nil {
		return err
	}
	defer func() {
		//fmt.Printf("return folderScanner closing: %v\n", path)
		folderScanner.Close()
		//fmt.Printf("return folderScanner closed: %v\n", path)
	}()
	for newDir := range dirOut {
		newInfo := newDir.(*fc.PathInfo)
		//fmt.Printf("recursive scan out: %v\n", newInfo.Path)
		err := newInfo.Err
		path := newInfo.Path
		fi := newInfo.Stat
		if err != nil {
			//fmt.Printf("folderScanner: %v\n", err)
			if ignoreScanError {
				continue
			}
			return fmt.Errorf("folderScanner.Scan %s: %v", newInfo.Path, err)
		}
		if newInfo.IsFolder == false {
			return fmt.Errorf("folderScanner.Scan %s: not a dir, %v", newInfo.Path, err)
		}
		err = self.addPath(stage, path, fi, true)
		if err != nil {
			if strings.HasSuffix(err.Error(), "no space left on device") {
				//fmt.Printf("return self.addPath(stage, %s, fi, recursive): %v\n", path, err)
				return fmt.Errorf("need more /proc/sys/fs/inotify/max_user_watches when watch %s: %v", path, err)
			}
			//fmt.Printf("ignoreScanError self.addPath(stage, path, fi, recursive): %v\n", err)
			if ignoreScanError {
				continue
			}
			return err
		}
		select {
		case <-self.scanDone:
			// already closed
			return fmt.Errorf("watch scan abort by user closed: %s", path)
		default:
		}
	}
	return nil
}

// GetEventChan gets event chan.
func (self *PathWatcher) GetEventChan() <-chan interface{} {
	return self.events.Out()
}

// SetThreshold, ns
func (self *PathWatcher) SetThreshold(l int64) int64 {
	old := self.threshold
	self.threshold = l
	return old
}

// SetMaxCacheIdle
func (self *PathWatcher) SetMaxCacheIdle(l time.Duration) time.Duration {
	old := self.maxCacheIdle
	// min 1000000ns, 1ms
	if l < 1000000 {
		return old
	}
	self.maxCacheIdle = l
	return old
}

// SetWatchFilter
// filter effect scanning path
// inc == true to set INCLUDE filter
// inc == false to set EXCLUDE filter
func (self *PathWatcher) SetWatchFilter(inc bool, pattern string) error {
	if inc {
		return self.watchIncludeFilter(pattern)
	}
	return self.watchExcludeFilter(pattern)
}

// DelWatchFilter
// filter effect scanning path
// inc == true to del INCLUDE filter
// inc == false to del EXCLUDE filter
func (self *PathWatcher) DelWatchFilter(inc bool, pattern string) error {
	self.miscMutex.Lock()
	defer self.miscMutex.Unlock()
	if inc {
		if _, ok := self.watchIncRegex[pattern]; ok {
			delete(self.watchIncRegex, pattern)
		}
	} else {
		if _, ok := self.watchExcRegex[pattern]; ok {
			delete(self.watchExcRegex, pattern)
		}
	}
	return nil
}

// watchIncludeFilter
// filter effect output only
func (self *PathWatcher) watchIncludeFilter(pattern string) error {
	self.miscMutex.Lock()
	defer self.miscMutex.Unlock()
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	self.watchIncRegex[pattern] = re
	return nil
}

// watchExcludeFilter
// filter effect output only
func (self *PathWatcher) watchExcludeFilter(pattern string) error {
	self.miscMutex.Lock()
	defer self.miscMutex.Unlock()
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	self.watchExcRegex[pattern] = re
	return nil
}

// watchMatch return false if path should not be watch
func (self *PathWatcher) watchMatch(newPath string) bool {
	// check regexp
	var match string
	var mOk bool
	if len(self.watchIncRegex) > 0 {
		mOk = false
		for match, _ = range self.watchIncRegex {
			if self.watchIncRegex[match].MatchString(newPath) == true {
				fmt.Println("watchInclude", match, "match", newPath)
				mOk = true
				break
			}
		}
		if mOk == false {
			return false
		}
	}
	if len(self.watchExcRegex) > 0 {
		mOk = false
		for match, _ = range self.watchExcRegex {
			if self.watchExcRegex[match].MatchString(newPath) == true {
				mOk = true
				fmt.Println("watchExclude", match, "match", newPath)
				break
			}
		}
		if mOk == true {
			return false
		}
	}
	return true
}

//
