//
// fswatcher demo
//

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	//rd "runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/wheelcomplex/fswatcher"
	//	"github.com/wheelcomplex/misc"
)

var cpuNum *int     // -c
var pathStr *string // -p
var statFlag *bool  // -v
var debugFlag *bool // -D
var modFlag *string // -m

func main() {
	modFlag = flag.String("m", "watch", "run module")
	pathStr = flag.String("p", "/tmp", "path to scan")
	cpuNum = flag.Int("c", 1, "use cpu number")
	statFlag = flag.Bool("v", false, "show stat")
	debugFlag = flag.Bool("D", false, "show debug")

	flag.Parse()
	runtime.GOMAXPROCS(*cpuNum)

	if *modFlag == "fmt" {
		dum := make(map[int]struct{})
		for i := int(0); i < 1e8; i++ {
			dum[i] = struct{}{}
		}
		println("start to dump")
		fmt.Printf("dum %v\n", dum)
		return
	}

	if *modFlag == "mkdir" {
		os.Exit(mkdir())
	}
	if *modFlag == "mkdir2" {
		os.Exit(mkdir2())
	}
	if *modFlag == "mkdir3" {
		os.Exit(mkdir3())
	}
	if *modFlag == "mkdir4" {
		os.Exit(mkdir4())
	}
	if *modFlag == "mkdir5" {
		os.Exit(mkdir5())
	}
	if *modFlag == "rmdir" {
		os.Exit(rmdir())
	}

	if *modFlag == "rmdir3" {
		os.Exit(rmdir3())
	}

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	// 8 watcher
	demo := fswatcher.NewPathWatcher(3)
	//fmt.Printf("fswatcher.NewWatcher: %v\n", 1024)
	defer func() {
		fmt.Printf("demo.defer closing...\n")
		//time.Sleep(1e9)
		demo.Close()
	}()

	demo.SetThreshold(1e5)
	//demo.SetThreshold(0)
	//fmt.Printf("demo.SetThreshold(%v)\n", 5)
	demo.SetMaxCacheIdle(5e9)
	//fmt.Printf("demo.SetMaxCacheIdle(%v)\n", 8e9)

	eventCh, err := demo.WatchRecursive(*pathStr, true)
	//fmt.Printf("demo.WatchRecursive(%s) scan end %v, %v ...\n", *pathStr, eventCh, err)
	if err != nil {
		fmt.Printf("demo.WatchRecursive(%s) error: %v\n", *pathStr, err)
		return
	}
	fmt.Printf("demo.WatchRecursive(%s) waiting event %v, %v ...\n", *pathStr, eventCh, err)
	//go func() {
	//time.Sleep(3e9)
	//fmt.Println("auto closing")
	//demo.Close()
	//}()
	starts := time.Now()
	var evcnt int64
	var everr int64
	var scancnt int64
	evMap := make(map[uint64]*fswatcher.ActEvent)
	if *statFlag {
		go func() {
			tk := time.NewTicker(5e9) // one second tick
			ts := time.Now()
			defer tk.Stop()
			var pre, cur uint64
			for {
				//runtime.GC()
				//rd.FreeOSMemory()
				wc, cache, pending := demo.Stat()
				ms := &runtime.MemStats{}
				runtime.ReadMemStats(ms)
				cur = ms.Alloc + ms.Sys
				if pre != cur {
					fmt.Printf("MEM Used %d/Res %d,  watching %d, cache %d, pending %d, event %d(scan %d), error %d, timing %v\n", ms.Alloc/1024/1024, ms.Sys/1024/1024, wc, cache, pending, evcnt, scancnt, everr, ts.Sub(starts))
					pre = cur
				}
				ts = <-tk.C
			}
		}()
	}
	//for _ = range eventCh {
	//}
	for ev := range eventCh {
		////slow down output
		//for i := 0; i < 5; i++ {
		//	misc.UUID()
		//}
		event := ev.(*fswatcher.ActEvent)
		if event.Stage == fswatcher.STAGE_INIT {
			scancnt++
		}
		//evMap[event.Inode] = event
		if event.Err == nil {
			if *debugFlag {
				fmt.Printf("eventCh: %v\n", event)
			}
			evcnt++
		} else {
			//if *debugFlag {
			fmt.Printf("eventCh Error: %v\n", event)
			//}
			everr++
			//break
		}
	}
	fmt.Printf("demo.WatchRecursive(%s) end, map %d, event %d, error %d, timing %d\n", *pathStr, len(evMap), evcnt, everr, time.Now().Sub(starts))
	time.Sleep(1e9)
	return
}

func rmdir3() int {
	dirmu := sync.Mutex{}
	rootdir := "watchroot3"
	oldpath, _ := os.Getwd()
	wg := sync.WaitGroup{}
	var cnt int64
	os.Mkdir(rootdir, os.ModePerm)
	basedir := oldpath + "/" + rootdir + "/"
	for i := int64(0); i < 1000000; {
		wg.Add(1)
		go func(start int64) {
			for j := int64(0); j < 100000; j++ {
				dirb := basedir + strconv.Itoa(int(j+start))
				if err := os.Remove(dirb); err != nil {
					//fmt.Println("rmdir", dirb, err)
					//return
				}
				//fmt.Println("mkdir", dirb)
				dirmu.Lock()
				cnt++
				dirmu.Unlock()
			}
			wg.Done()
		}(i)
		i = i + 100000
	}
	wg.Wait()
	fmt.Println("rmdir3", rootdir, cnt)
	return 0
}

func mkdir3() int {
	dirmu := sync.Mutex{}
	rootdir := "watchroot3"
	oldpath, _ := os.Getwd()
	wg := sync.WaitGroup{}
	var cnt int64
	os.Mkdir(rootdir, os.ModePerm)
	basedir := oldpath + "/" + rootdir + "/"
	for i := int64(0); i < 1000000; {
		wg.Add(1)
		go func(start int64) {
			for j := int64(0); j < 100000; j++ {
				dirb := basedir + strconv.Itoa(int(j+start))
				if err := os.Mkdir(dirb, os.ModePerm); err != nil {
					fmt.Println("mkdir", dirb, err)
					//return
				}
				//fmt.Println("mkdir", dirb)
				dirmu.Lock()
				cnt++
				dirmu.Unlock()
			}
			wg.Done()
		}(i)
		i = i + 100000
	}
	wg.Wait()
	fmt.Println("mkdir", rootdir, cnt)
	return 0
}

func mkdir2() int {
	dirmu := sync.Mutex{}
	rootdir := "watchroot2"
	oldpath, _ := os.Getwd()
	wg := sync.WaitGroup{}
	var cnt int64
	os.Mkdir(rootdir, os.ModePerm)
	for i := 0; i < 100; i++ {
		dira := oldpath + "/" + rootdir + "/" + strconv.Itoa(i)
		if err := os.Mkdir(dira, os.ModePerm); err != nil {
			fmt.Println("mkdir", dira, err)
			return 1
		}
		dirmu.Lock()
		cnt++
		dirmu.Unlock()
		wg.Add(1)
		go func(start string) {
			for j := 0; j < 100; j++ {
				dirb := start + "/" + strconv.Itoa(j)
				if err := os.Mkdir(dirb, os.ModePerm); err != nil {
					fmt.Println("mkdir", dirb, err)
					return
				}
				//fmt.Println("mkdir", dirb)
				dirmu.Lock()
				cnt++
				dirmu.Unlock()
			}
			wg.Done()
		}(dira)
	}
	wg.Wait()
	fmt.Println("mkdir", rootdir, cnt)
	return 0
}

func mkdir() int {
	dirmu := sync.Mutex{}
	rootdir := "watchroot"
	oldpath, _ := os.Getwd()
	wg := sync.WaitGroup{}
	var cnt int64
	os.Mkdir(rootdir, os.ModePerm)
	for i := 0; i < 1000; i++ {
		dira := oldpath + "/" + rootdir + "/" + strconv.Itoa(i)
		if err := os.Mkdir(dira, os.ModePerm); err != nil {
			fmt.Println("mkdir", dira, err)
			return 1
		}
		dirmu.Lock()
		cnt++
		dirmu.Unlock()
		wg.Add(1)
		go func(start string) {
			for j := 0; j < 100; j++ {
				dirb := start + "/" + strconv.Itoa(j)
				if err := os.Mkdir(dirb, os.ModePerm); err != nil {
					fmt.Println("mkdir", dirb, err)
					return
				}
				//fmt.Println("mkdir", dirb)
				dirmu.Lock()
				cnt++
				dirmu.Unlock()
			}
			wg.Done()
		}(dira)
	}
	wg.Wait()
	fmt.Println("mkdir", rootdir, cnt)
	return 0
}

func mkdir4() int {
	dirmu := sync.Mutex{}
	rootdir := "watchroot"
	oldpath, _ := os.Getwd()
	wg := sync.WaitGroup{}
	var cnt int64
	os.Mkdir(rootdir, os.ModePerm)
	for i := 0; i < 1000; i++ {
		dira := oldpath + "/" + rootdir + "/" + strconv.Itoa(i)
		if err := os.Mkdir(dira, os.ModePerm); err != nil {
			fmt.Println("mkdir", dira, err)
			return 1
		}
		dirmu.Lock()
		cnt++
		dirmu.Unlock()
		wg.Add(1)
		go func(start string) {
			for j := 0; j < 1000; j++ {
				dirb := start + "/" + strconv.Itoa(j)
				if err := os.Mkdir(dirb, os.ModePerm); err != nil {
					fmt.Println("mkdir", dirb, err)
					return
				}
				//fmt.Println("mkdir", dirb)
				dirmu.Lock()
				cnt++
				dirmu.Unlock()
			}
			wg.Done()
		}(dira)
	}
	wg.Wait()
	fmt.Println("mkdir", rootdir, cnt)
	return 0
}

func mkdir5() int {
	dirmu := sync.Mutex{}
	rootdir := "watchroot"
	oldpath, _ := os.Getwd()
	wg := sync.WaitGroup{}
	var cnt int64
	os.Mkdir(rootdir, os.ModePerm)
	for i := 0; i < 100; i++ {
		dira := oldpath + "/" + rootdir + "/" + strconv.Itoa(i)
		if err := os.Mkdir(dira, os.ModePerm); err != nil {
			//fmt.Println("mkdir", dira, err)
			//return 1
		}
		dirmu.Lock()
		cnt++
		dirmu.Unlock()
		wg.Add(1)
		go func(start string) {
			for j := 0; j < 100; j++ {
				dirb := start + "/" + strconv.Itoa(j)
				if err := os.Mkdir(dirb, os.ModePerm); err != nil {
					//fmt.Println("mkdir", dirb, err)
					//return
					//continue
				}
				//fmt.Println("mkdir", dirb)
				dirmu.Lock()
				cnt++
				dirmu.Unlock()
				wg.Add(1)
				go func(start string) {
					for j := 0; j < 100; j++ {
						dirb := start + "/" + strconv.Itoa(j)
						if err := os.Mkdir(dirb, os.ModePerm); err != nil {
							//fmt.Println("mkdir", dirb, err)
							//return
							//continue
						}
						//fmt.Println("mkdir", dirb)
						dirmu.Lock()
						cnt++
						dirmu.Unlock()
					}
					wg.Done()
				}(dirb)
			}
			wg.Done()
		}(dira)
	}
	wg.Wait()
	fmt.Println("mkdir", rootdir, cnt)
	return 0
}

//
func rmdir() int {
	runtime.GOMAXPROCS(1)
	dirmu := sync.Mutex{}
	rootdir := "watchroot"
	oldpath, _ := os.Getwd()
	wg := sync.WaitGroup{}
	var cnt int64
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		dira := oldpath + "/" + rootdir + "/" + strconv.Itoa(i)
		go func(start string) {
			for j := 0; j < 1000; j++ {
				dirb := start + "/" + strconv.Itoa(j)
				if err := os.Remove(dirb); err != nil {
					//fmt.Println("rmdir", dirb, err)
					continue
				}
				dirmu.Lock()
				cnt++
				dirmu.Unlock()
			}
			wg.Done()
		}(dira)
	}
	wg.Wait()
	for i := 0; i < 1000; i++ {
		dira := oldpath + "/" + rootdir + "/" + strconv.Itoa(i)
		if err := os.Remove(dira); err != nil {
			//fmt.Println("rmdir", dira, err)
			continue
		}
		dirmu.Lock()
		cnt++
		dirmu.Unlock()
	}
	fmt.Println("rmdir", rootdir, cnt)
	return 0
}

//
//
//
//
//
//
//
//
//
//
//
