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
	//"runtime"
	rd "runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	fc "github.com/wheelcomplex/folderscanner"
	"github.com/wheelcomplex/fsnotify"
	"github.com/wheelcomplex/goqueue/stack"
)

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
// NOTE: when events > 100000/s, a few event may lost and do not handled
type PathWatcher struct {
	pRawEvents    *stack.Stack                 // raw event stack
	rRawEvents    *stack.Stack                 // raw event stack
	events        *stack.Stack                 // output stack
	eventsIn      chan<- interface{}           // in
	pWatcher      map[uint64]*fsnotify.Watcher // group of watcher
	rWatcher      map[uint64]*fsnotify.Watcher // group of watcher
	evWg          sync.WaitGroup               // goroutine sync
	cache         map[uint64]*cacheInfo        // event cache, index by FileInfo.Inode
	cacheMu       sync.Mutex                   // lock
	watcherNum    uint64                       // output channel buffer size
	isClosed      bool                         // is watcher is working
	closing       chan struct{}                // tell eventProc to closing
	threshold     int64                        // Throughput Limitations
	maxCacheIdle  time.Duration                //
	watchIncRegex map[string]*regexp.Regexp    // compiled watchInclude filter
	watchExcRegex map[string]*regexp.Regexp    // compiled watchExclude filter
	scanDone      chan error                   // scan result
	scanMu        sync.Mutex                   // lock
	miscMutex     sync.Mutex                   // lock
	sumMu         sync.Mutex                   // lock
	lazyAddStack  *stack.Stack                 // recursive watch new dir
	lazyRemoveCh  chan string                  // recursive watch new dir
	hasher        hash.Hash64                  // string to uint hasher
	wg            sync.WaitGroup               // goroutine sync
	overflowTS    chan time.Time               // notify queue overflow ts
	rootDirs      map[string]struct{}
}

// NewPathWatcher creates an instance of PathWatcher.
func NewPathWatcher(size int) *PathWatcher {
	if size < 1 {
		size = 1
	}
	self := &PathWatcher{
		watcherNum:    uint64(size),
		threshold:     IgnoreThresholdRange,
		maxCacheIdle:  5e9, // 5 seconds
		watchIncRegex: make(map[string]*regexp.Regexp),
		watchExcRegex: make(map[string]*regexp.Regexp),
		scanDone:      make(chan error, 1),
		isClosed:      true,
		hasher:        fnv.New64a(),
		wg:            sync.WaitGroup{},
		evWg:          sync.WaitGroup{},
		overflowTS:    make(chan time.Time, 8192),
	}
	return self
}

// Sum64a
func (self *PathWatcher) Sum64a(data string) uint64 {
	self.sumMu.Lock()
	defer self.sumMu.Unlock()
	self.hasher.Reset()
	self.hasher.Write([]byte(data))
	return self.hasher.Sum64()
}

// pPurge hash and Purge path in pWatcher
func (self *PathWatcher) pPurge(path string) error {
	return self.pWatcher[uint64(self.Sum64a(path)%self.watcherNum)].Purge(path)
}

// rPurge hash and Purge path in rWatcher
func (self *PathWatcher) rPurge(path string) error {
	return self.rWatcher[uint64(self.Sum64a(path)%self.watcherNum)].Purge(path)
}

// pAdd hash and add path to pWatcher
func (self *PathWatcher) pAdd(path string) error {
	return self.pWatcher[uint64(self.Sum64a(path)%self.watcherNum)].Add(path)
}

// rAdd hash and add path to rWatcher
func (self *PathWatcher) rAdd(path string) error {
	return self.rWatcher[uint64(self.Sum64a(path)%self.watcherNum)].Add(path)
}

// rIsWatched hash and check path in rWatcher
func (self *PathWatcher) rIsWatched(path string) bool {
	return self.rWatcher[uint64(self.Sum64a(path)%self.watcherNum)].IsWatched(path)
}

// pIsWatched hash and check path in rWatcher
func (self *PathWatcher) pIsWatched(path string) bool {
	return self.pWatcher[uint64(self.Sum64a(path)%self.watcherNum)].IsWatched(path)
}

// Stat watching, cache, pending event
func (self *PathWatcher) Stat() (uint64, uint64, uint64) {
	if self.isClosed {
		return 0, 0, 0
	}
	return uint64(self.Count()), uint64(len(self.cache)), self.pRawEvents.GetCacheSize() + self.rRawEvents.GetCacheSize()
}

// Count
func (self *PathWatcher) Count() uint64 {
	if self.isClosed {
		return 0
	}
	tc := uint64(0)
	for i := uint64(0); i < self.watcherNum; i++ {
		tc = tc + self.pWatcher[i].Count() + self.rWatcher[i].Count()
	}
	return tc
}

func (self *PathWatcher) newWatchHandle() error {
	var err error
	self.miscMutex.Lock()
	defer self.miscMutex.Unlock()
	if self.isClosed == false {
		// no closed, do not need re-initial
		return nil
	}
	//
	self.rootDirs = make(map[string]struct{})
	self.isClosed = false
	self.closing = make(chan struct{}, 128)
	self.cache = make(map[uint64]*cacheInfo)

	self.pRawEvents = stack.NewStack(10240, -1, false)
	self.rRawEvents = stack.NewStack(10240, -1, false)
	//
	self.events = stack.NewStack(256, -1, false)
	self.eventsIn = self.events.In()
	self.lazyAddStack = stack.NewStack(256, -1, false)
	self.lazyRemoveCh = make(chan string, 1024)
	self.scanDone = make(chan error, 8)
	//
	self.pWatcher = make(map[uint64]*fsnotify.Watcher)
	self.rWatcher = make(map[uint64]*fsnotify.Watcher)
	for i := uint64(0); i < self.watcherNum; i++ {
		self.pWatcher[i], err = fsnotify.NewWatcher(int(self.watcherNum) * 4096)
		if err != nil {
			return err
		}
		self.rWatcher[i], err = fsnotify.NewWatcher(int(self.watcherNum) * 4096)
		if err != nil {
			return err
		}
		go self.pEventRead(i)
		go self.rEventRead(i)
		go self.pErrorRead(i)
		go self.rErrorRead(i)
		go self.pEventProc(i + 10100)
		go self.pEventProc(i + 10200)
		go self.pEventProc(i + 10300)
		go self.rEventProc(i + 11000)
		go self.rEventProc(i + 12000)
		go self.rEventProc(i + 13000)
	}
	go self.cacheMgr()
	//
	go self.watchMgr()
	//
	//println("newWatchHandle done")
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
	for i := uint64(0); i < self.watcherNum; i++ {
		self.pWatcher[i].Close()
		self.rWatcher[i].Close()
	}
	println("waiting for eventRead goroutine exit")
	self.evWg.Wait()
	// will blocking to wait for flush
	self.pRawEvents.Close()
	self.rRawEvents.Close()
	//
	close(self.closing)
	println("waiting for mgr goroutine exit")
	self.wg.Wait()
	//
	self.cache = nil
	//
	self.lazyAddStack.Close()
	close(self.lazyRemoveCh)
	//
	println("waiting for out stack exit")
	// will blocking to wait for raw stack stop
	self.events.Close()
	//
	fmt.Printf("PathWatcher %p closed\n", self)
	return nil
}

// pErrorRead running in goroutine and forward error event to output
func (self *PathWatcher) pErrorRead(idx uint64) {
	//fmt.Printf("errorRead(%v) running ...\n", recursive)
	self.evWg.Add(1)
	defer self.evWg.Done()
	var everror error
	// fast read event, if event pending in epoll_wait will case event lost
	for everror = range self.pWatcher[idx].Errors {
		self.eventSend(newActEvent(STAGE_WATCH, 0, DUMMY_EVENT, 0, 0, false, everror), nil)
	}
	println("pErrorRead", idx, "exited")
	return
}

// rErrorRead running in goroutine and forward error event to output
func (self *PathWatcher) rErrorRead(idx uint64) {
	//fmt.Printf("errorRead(%v) running ...\n", recursive)
	self.evWg.Add(1)
	defer self.evWg.Done()
	var everror error
	// fast read event, if event pending in epoll_wait will case event lost
	for everror = range self.rWatcher[idx].Errors {
		self.eventSend(newActEvent(STAGE_WATCH, 0, DUMMY_EVENT, 0, 0, false, everror), nil)
	}
	println("rErrorRead", idx, "exited")
	return
}

// pEventRead running in goroutine and forward event to stack
func (self *PathWatcher) pEventRead(idx uint64) {
	self.evWg.Add(1)
	defer self.evWg.Done()
	var event fsnotify.Event
	rawIn := self.pRawEvents.In()
	for event = range self.pWatcher[idx].Events {
		rawIn <- event
	}
	println("pEventRead", idx, "exited")
}

// rEventRead running in goroutine and forward event to stack
func (self *PathWatcher) rEventRead(idx uint64) {
	self.evWg.Add(1)
	defer self.evWg.Done()
	var event fsnotify.Event
	rawIn := self.rRawEvents.In()
	for event = range self.rWatcher[idx].Events {
		rawIn <- event
		// direct add
		// TODO: test lost
		//if event.IsCreate() && len(event.Name) > 0 {
		//	self.rAdd(event.Name)
		//}
	}
	println("rEventRead", idx, "exited")
}

// pEventProc running in goroutine and forward rawEvents to output
func (self *PathWatcher) pEventProc(idx uint64) {
	//
	//fmt.Printf("pEventProc(%v) running ...\n", recursive)
	var evInterface interface{}
	var event fsnotify.Event
	//
	rawOut := self.pRawEvents.Out()
	for evInterface = range rawOut {
		event = evInterface.(fsnotify.Event)
		//
		//evcnt++
		//
		hid := self.Sum64a(event.Name)
		//
		if event.IsOverFlow() {
			select {
			case self.overflowTS <- time.Now():
				fmt.Printf("%d, pEventProc event %+v\n", hid, event)
			default:
				fmt.Printf("%d, drop pEventProc event %+v\n", hid, event)
			}
			continue
		}
		//fmt.Printf("%d, pEventProc event %+v\n", hid, event)
		// you can not stat a delete file...
		if event.IsDelete() {
			//fmt.Printf("%d, removeWatch(%v) event %+v\n", hid, recursive, event)
			// adjust with arbitrary value because it was deleted
			// before it got here
			self.eventSend(newActEvent(STAGE_WATCH, hid, event, time.Now().UnixNano()-10, 0, false, nil), nil)
			continue
		}
		if self.watchMatch(event.Name) == false {
			// TODO: test match
			fmt.Printf("IgnorePath pEventProc event %+v\n", event)
			continue
		}
		//fmt.Printf("%d, pEventProc(%v) event %+v\n", hid, recursive, event)
		fi, err := os.Lstat(event.Name)
		//rename send two events,one old file,one new file,here ignore old one
		if os.IsNotExist(err) {
			continue
		}
		//if err != nil {
		//      // too many levels of symbolic links/fi=<nil>
		//      fmt.Printf("path exist but error: err=%v/fi=%v/event=%v\n", err, fi, event)
		//}
		if fi == nil {
			self.eventSend(newActEvent(STAGE_WATCH, hid, event, time.Now().UnixNano()-10, 0, false, nil), nil)
			continue
		}
		self.eventSend(newActEvent(STAGE_WATCH, hid, event, fi.ModTime().UnixNano(), fi.Sys().(*syscall.Stat_t).Ino, fi.IsDir(), nil), fi)
		//
		///////////////////////////
	}
	println("pEventProc", idx, "exited")
	return
}

// rEventProc running in goroutine and forward event to output
func (self *PathWatcher) rEventProc(idx uint64) {
	//fmt.Printf("rEventProc(%v) running ...\n", recursive)
	var evInterface interface{}
	var event fsnotify.Event
	//
	lazyIn := self.lazyAddStack.In()
	rawOut := self.rRawEvents.Out()
	for evInterface = range rawOut {
		event = evInterface.(fsnotify.Event)
		//
		//evcnt++
		//
		hid := self.Sum64a(event.Name)
		//
		if event.IsOverFlow() {
			select {
			case self.overflowTS <- time.Now():
				fmt.Printf("%d, rEventProc event %+v\n", hid, event)
			default:
				fmt.Printf("%d, drop rEventProc event %+v\n", hid, event)
			}
			continue
		}
		//fmt.Printf("%d, rEventProc(%v) event %+v\n", hid, recursive, event)
		// you can not stat a delete file...
		if event.IsDelete() {
			self.rPurge(event.Name)
			//self.removeWatch <- &idPath{id: hid, path: event.Name}
			//fmt.Printf("%d, removeWatch(%v) event %+v\n", hid, recursive, event)
			// adjust with arbitrary value because it was deleted
			// before it got here
			self.eventSend(newActEvent(STAGE_WATCH, hid, event, time.Now().UnixNano()-10, 0, false, nil), nil)
			continue
		}
		if self.watchMatch(event.Name) == false {
			// TODO: test match
			fmt.Printf("%d IgnorePath rEventProc event %+v\n", idx, event)
			continue
		}
		//fmt.Printf("%d, rEventProc(%v) event %+v\n", hid, recursive, event)
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
		if isDir && event.IsCreate() {
			// first watch, direct watch, no recursive
			self.rAdd(event.Name)
			// recursive scan
			lazyIn <- event.Name
		} else {
			//fmt.Printf("%d, rEventProc(%v), isDir %v, IsCreate %v, event %+v\n", hid, recursive, isDir, event.IsCreate(), event)
		}
		///////////////////////////
	}
	println("rEventProc", idx, "exited")
	return
}

// simple rWatch
func (self *PathWatcher) lazyRWatch(path string) int64 {
	//
	var addCount int64
	//
	folderScanner := fc.NewFolderScanner(int(self.watcherNum))
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
		return addCount
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
		key := newInfo.Path
		fi := newInfo.Stat
		if err != nil {
			continue
		}
		if self.rIsWatched(key) {
			continue
		}
		err = self.rAdd(key)
		if err == nil {
			addCount++
		}
		self.eventSend(&ActEvent{
			//Stage:    STAGE_LAZY,
			Stage:    STAGE_WATCH,
			Event:    fsnotify.NewEvent(fsnotify.Create|fsnotify.Write, key),
			IsFolder: true,
			UnixNano: fi.ModTime().UnixNano(),
			Inode:    fi.Sys().(*syscall.Stat_t).Ino,
			Err:      err,
			Id:       self.Sum64a(key),
		}, fi)
		select {
		case <-self.scanDone:
			// already closed
			fmt.Printf("watch scan abort by user closed: %s", path)
			return addCount
		default:
		}
	}
	return addCount
}

//
func (self *PathWatcher) cacheMgr() {
	self.wg.Add(1)
	defer self.wg.Done()
	tk := time.NewTicker(1e9)
	defer tk.Stop()
	memtk := time.NewTicker(5e9)
	defer memtk.Stop()
	var changed bool
	for {
		select {
		case <-self.closing:
			println("cachMgr exited")
			return
		case ts := <-tk.C:
			if (self.pRawEvents.GetCacheSize() + self.rRawEvents.GetCacheSize()) == 0 {
				for name, _ := range self.cache {
					self.cacheMu.Lock()
					if ts.Sub(self.cache[name].last) > self.maxCacheIdle {
						// debug
						//fmt.Printf("clean idle %v(%v/%v)\n", name, ts.Sub(self.cache[name].last), self.maxCacheIdle)
						delete(self.cache, name)
						changed = true
					}
					self.cacheMu.Unlock()
				}
			}
		case <-memtk.C:
			if len(self.cache) == 0 && (self.pRawEvents.GetCacheSize()+self.rRawEvents.GetCacheSize()) == 0 && changed {
				rd.FreeOSMemory()
				changed = false
			}
		}
	}
}

//
func parentCheck(list map[string]struct{}, path string) bool {
	paths := strings.Split(path, "/")
	//fmt.Println("checking", path, paths)
	np := ""
	chklen := len(paths) - 1
	for sp := 1; sp < chklen; sp++ {
		np = np + "/" + paths[sp]
		//println("sub checking", np)
		if _, ok := list[np]; ok {
			//println("for parent", np, "parentCheck false", path)
			return false
		}
	}
	return true
}

//
func (self *PathWatcher) Dump(tip string) {
	println("\n----DUMP----", tip, "\n")
	for i := uint64(0); i < self.watcherNum; i++ {
		for path := range self.rWatcher[i].PathList() {
			println(i, path)
		}
	}
	println("\n------R------", tip, "\n")
	for i := uint64(0); i < self.watcherNum; i++ {
		for path := range self.pWatcher[i].PathList() {
			println(i, path)
		}
	}
	println("\n------P------", tip, "\n")
}

//
func (self *PathWatcher) watchMgr() {
	// signle thread, do not need lock
	self.wg.Add(1)
	defer self.wg.Done()
	tk := time.NewTicker(1e9)
	defer tk.Stop()
	lazyList := make(map[string]struct{})
	var npath interface{}
	var rpath string
	var rescann int
	lazyOut := self.lazyAddStack.Out()
	for {
		select {
		case <-self.closing:
			println("watchMgr exited")
			return
		case <-tk.C:
			rescann++
			// idle 5 seconds, start to scan parent
			if rescann >= 5 {
				lazygw := sync.WaitGroup{}
				subscan := 0
				for lazyPath, _ := range lazyList {
					delete(lazyList, lazyPath)
					lazygw.Add(1)
					subscan++
					go func() {
						//fmt.Printf("watchMgr, new lazyWatch %v || %v\n", lazyPath, rescann)
						//self.Dump("befor lazyRWatch" + lazyPath)
						if nw := self.lazyRWatch(lazyPath); nw > 0 {
							fmt.Printf("watchMgr, new lazyWatch %v || %v\n", nw, lazyPath)
							//self.Dump("after lazyRWatch" + lazyPath)
						}
						//fmt.Printf("watchMgr, end lazyWatch %v || %v\n", lazyPath, rescann)
						lazygw.Done()
					}()
					//fmt.Printf("watchMgr, new lazyWatch %v end.\n", lazyPath)
					if self.lazyAddStack.GetCacheSize() >= 2048 {
						println("lazyRWatch abort for too many new events", self.lazyAddStack.GetCacheSize())
						break
					}
					if subscan > 2 {
						subscan = 0
						// blocking
						lazygw.Wait()
					}
				}
				if subscan > 0 {
					lazygw.Wait()
				}
				//fmt.Printf("watchMgr, lazy watch %d end.\n", len(lazyList))
				rescann = 0
			}
		case npath = <-lazyOut:
			//
			rescann = 0
			ppath := filepath.Dir(npath.(string))
			if parentCheck(lazyList, ppath) {
				lazyList[ppath] = struct{}{}
			}
			//
		case rpath = <-self.lazyRemoveCh:
			go self.rPurge(rpath)
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
	if self.threshold > 0 && ae.Stage != STAGE_INIT && ae.Event.IsDelete() == false {
		self.cacheMu.Lock()
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
					self.cacheMu.Unlock()
					return
				}
			} else if fi == nil && oldFI != nil {
				if tsnow.UnixNano() < self.cache[ae.Id].last.UnixNano()+self.threshold {
					//fmt.Printf("SKKIPED, %d, delete/error threshold(%v) >= %v\n", evTag, self.threshold, (self.threshold+self.cache[ae.Id].last.UnixNano())-tsnow.UnixNano())
					self.cacheMu.Unlock()
					return
				}
			}
		}
		self.cache[ae.Id].last = tsnow
		// fi may be <nil>
		self.cache[ae.Id].list[evTag] = &fi
		self.cacheMu.Unlock()
	}
	self.eventsIn <- ae
	if ae.Stage == STAGE_LAZY && ae.Event.IsCreate() {
		// recursive scan lazy path
		self.lazyAddStack.In() <- ae.Event.Name
	}
	return
}

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
	//fmt.Printf("recursively newWatchHandle ok: %s\n", path)
	//
	self.rootDirs[path] = struct{}{}
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
	self.rootDirs[path] = struct{}{}
	//
	if err := self.watch(STAGE_INIT, path, false, ignoreScanError); err != nil {
		fmt.Printf("scan failed: %v\n", err)
		return nil, err
	}
	//fmt.Printf("scan ok: %s\n", path)
	return self.events.Out(), err
}

func (self *PathWatcher) addPath(stage int, path string, fi os.FileInfo, recursive bool) error {
	var err error
	if recursive || stage == STAGE_LAZY {
		err = self.rAdd(path)
	} else {
		err = self.pAdd(path)
	}
	self.eventSend(&ActEvent{
		Stage:    stage,
		Event:    fsnotify.NewEvent(fsnotify.Create|fsnotify.Write, path),
		IsFolder: true,
		UnixNano: fi.ModTime().UnixNano(),
		Inode:    fi.Sys().(*syscall.Stat_t).Ino,
		Err:      err,
		Id:       self.Sum64a(path),
	}, fi)
	return err
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
	//fmt.Printf("underdelay watch root addPath(%v): %v/%v\n", recursive, path, err)
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
	folderScanner := fc.NewFolderScanner(int(self.watcherNum))
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
