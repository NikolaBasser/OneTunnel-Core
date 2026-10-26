//go:build windows && onetunnel_safety_test

package main

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func securityAttributes() (*windows.SecurityAttributes, error) {
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func jobName(p plan) *uint16 {
	return windows.StringToUTF16Ptr(`Global\OneTunnelAcceptanceJob-` + p.RunID)
}

func createJob(p plan) (windows.Handle, error) {
	sa, err := securityAttributes()
	if err != nil {
		return 0, err
	}
	job, err := windows.CreateJobObject(sa, jobName(p))
	if err != nil {
		if job != 0 {
			windows.CloseHandle(job)
		}
		return 0, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func spawnWorker(p plan, job windows.Handle) error {
	args := windows.ComposeCommandLine([]string{p.Executable, "--mode", "worker", "--plan", p.GuardRoot + `\plan.json`})
	command, err := windows.UTF16FromString(args)
	if err != nil {
		return err
	}
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return err
	}
	defer attributes.Delete()
	jobs := [1]windows.Handle{job}
	const jobListAttribute = 0x0002000d // PROC_THREAD_ATTRIBUTE_JOB_LIST (Windows 10+).
	if err = attributes.Update(jobListAttribute, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs)); err != nil {
		return err
	}
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{}))}, ProcThreadAttributeList: attributes.List()}
	var pi windows.ProcessInformation
	if err = windows.CreateProcess(windows.StringToUTF16Ptr(p.Executable), &command[0], nil, nil, false, windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW|windows.EXTENDED_STARTUPINFO_PRESENT, nil, windows.StringToUTF16Ptr(p.GuardRoot), &si.StartupInfo, &pi); err != nil {
		return err
	}
	runtime.KeepAlive(jobs)
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	resumed := false
	defer func() {
		if !resumed {
			_ = windows.TerminateProcess(pi.Process, 1)
			_, _ = windows.WaitForSingleObject(pi.Process, 5000)
		}
	}()
	if _, err = windows.ResumeThread(pi.Thread); err != nil {
		return err
	}
	resumed = true
	return nil
}

func withGate(p plan, run func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	sa, err := securityAttributes()
	if err != nil {
		return err
	}
	mutex, err := windows.CreateMutex(sa, false, windows.StringToUTF16Ptr(`Global\OneTunnelAcceptanceGate-`+p.RunID))
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return err
	}
	defer windows.CloseHandle(mutex)
	status, err := windows.WaitForSingleObject(mutex, 5000)
	if err != nil {
		return err
	}
	if status != windows.WAIT_OBJECT_0 && status != windows.WAIT_ABANDONED {
		return errors.New("acceptance mutation gate unavailable")
	}
	defer windows.ReleaseMutex(mutex)
	return run()
}

func terminateOwnedJob(p plan) error {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("OpenJobObjectW")
	value, _, callErr := proc.Call(0x0004|0x0008, 0, uintptr(unsafe.Pointer(jobName(p)))) // QUERY | TERMINATE
	if value == 0 {
		if callErr == syscall.ERROR_FILE_NOT_FOUND {
			return nil
		}
		return callErr
	}
	job := windows.Handle(value)
	defer windows.CloseHandle(job)
	if err := windows.TerminateJobObject(job, 1); err != nil {
		return err
	}
	// JOBOBJECT_BASIC_ACCOUNTING_INFORMATION ends in four DWORD process counts.
	var accounting struct {
		Times                             [4]int64
		Faults, Total, Active, Terminated uint32
	}
	for i := 0; i < 50; i++ {
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil); err != nil {
			return err
		}
		if accounting.Active == 0 {
			return nil
		}
		windows.SleepEx(100, false)
	}
	return errors.New("owned worker job did not terminate")
}

func verifyWorkerJob(p plan) error {
	open := windows.NewLazySystemDLL("kernel32.dll").NewProc("OpenJobObjectW")
	value, _, err := open.Call(0x0004, 0, uintptr(unsafe.Pointer(jobName(p))))
	if value == 0 {
		return err
	}
	job := windows.Handle(value)
	defer windows.CloseHandle(job)
	var inside int32
	result, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(uintptr(windows.CurrentProcess()), uintptr(job), uintptr(unsafe.Pointer(&inside)))
	if result == 0 {
		return err
	}
	if inside == 0 {
		return errors.New("worker is not contained in the expected acceptance job")
	}
	return nil
}
