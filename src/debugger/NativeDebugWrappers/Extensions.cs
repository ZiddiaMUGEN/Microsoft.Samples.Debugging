using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

using Microsoft.Samples.Debugging.Native.Private;

namespace Microsoft.Samples.Debugging.Native
{
    public class OutputDebugStringNativeEvent : NativeEvent
    {
        private string m_cachedMessage;

        internal OutputDebugStringNativeEvent(
          NativePipeline pipeline,
          ref DebugEventHeader header,
          ref DebugEventUnion union)
          : base(pipeline, ref header, ref union)
        {
            this.ContinueStatus = NativeMethods.ContinueStatus.DBG_CONTINUE;
        }

        public string ReadMessage()
        {
            if (this.m_cachedMessage == null)
                this.m_cachedMessage = this.m_union.OutputDebugString.ReadMessageFromTarget((IMemoryReader)this.Process);
            return this.m_cachedMessage;
        }

        public override string ToString() => string.Format("OutputDebugString:tid={0}, message={1}", (object)this.ThreadId, (object)this.ReadMessage());
    }

    public class UnloadDllNativeEvent : DllBaseNativeEvent
    {
        public override IntPtr BaseAddress => this.m_union.UnloadDll.lpBaseOfDll;

        internal UnloadDllNativeEvent(
          NativePipeline pipeline,
          ref DebugEventHeader header,
          ref DebugEventUnion union)
          : base(pipeline, ref header, ref union)
        {
        }

        public override string ToString() => string.Format("DLL unload:Address 0x{0},{1}", (object)this.BaseAddress.ToString("x"), this.Module == null ? (object)"unknown" : (object)this.Module.Name);

        public override void DoCleanupForContinue()
        {
            NativeDbgModule module = this.Module;
            if (module == null)
                return;
            module.CloseHandle();
            this.Process.RemoveModule(module.BaseAddress);
        }
    }

    public sealed class NativePipeline : IDisposable
    {
        private bool m_KillOnExit = true;
        private Dictionary<int, NativeDbgProcess> m_processes = new Dictionary<int, NativeDbgProcess>();

        public bool KillOnExit
        {
            get => this.m_KillOnExit;
            set
            {
                this.m_KillOnExit = value;
                NativeMethods.DebugSetProcessKillOnExit(value);
            }
        }

        private NativeDbgProcess CreateNew(int processId)
        {
            NativeDbgProcess nativeDbgProcess = new NativeDbgProcess(processId);
            this.m_processes[processId] = nativeDbgProcess;
            return nativeDbgProcess;
        }

        internal NativeDbgProcess GetOrCreateProcess(int processId)
        {
            NativeDbgProcess nativeDbgProcess;
            return !this.m_processes.TryGetValue(processId, out nativeDbgProcess) ? this.CreateNew(processId) : nativeDbgProcess;
        }

        public NativeDbgProcess GetProcess(int processId)
        {
            NativeDbgProcess nativeDbgProcess;
            if (this.m_processes.TryGetValue(processId, out nativeDbgProcess))
                return nativeDbgProcess;
            throw new InvalidOperationException("Process " + (object)processId + " is not being debugged by this pipeline. The process may have exited or been detached from.");
        }

        internal void RemoveProcess(int pid)
        {
            this.GetProcess(pid).Dispose();
            this.m_processes.Remove(pid);
        }

        public NativeDbgProcess Attach(int processId)
        {
            if (!NativeMethods.DebugActiveProcess((uint)processId))
            {
                int lastWin32Error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException("Failed to attach to process id " + (object)processId + "error=" + (object)lastWin32Error);
            }
            return this.CreateNew(processId);
        }

        public NativeDbgProcess CreateProcessChildDebug(
          string application,
          string commandArgs)
        {
            return this.CreateProcessDebugWorker(application, commandArgs, NativeMethods.CreateProcessFlags.DEBUG_PROCESS);
        }

        public NativeDbgProcess CreateProcessDebug(
          string application,
          string commandArgs)
        {
            return this.CreateProcessDebugWorker(application, commandArgs, NativeMethods.CreateProcessFlags.DEBUG_PROCESS | NativeMethods.CreateProcessFlags.DEBUG_ONLY_THIS_PROCESS);
        }

        private NativeDbgProcess CreateProcessDebugWorker(
          string application,
          string commandArgs,
          NativeMethods.CreateProcessFlags flags)
        {
            if (application == null)
                throw new ArgumentException("can't be null", nameof(application));
            if (commandArgs != null)
                commandArgs = application + " " + commandArgs;
            PROCESS_INFORMATION lpProcessInformation = new PROCESS_INFORMATION();
            STARTUPINFO lpStartupInfo = new STARTUPINFO();
            NativeMethods.CreateProcess(application, commandArgs, IntPtr.Zero, IntPtr.Zero, false, NativeMethods.CreateProcessFlags.CREATE_NEW_CONSOLE | flags, IntPtr.Zero, (string)null, lpStartupInfo, lpProcessInformation);
            NativeMethods.CloseHandle(lpProcessInformation.hProcess);
            NativeMethods.CloseHandle(lpProcessInformation.hThread);
            return this.CreateNew(lpProcessInformation.dwProcessId);
        }

        public void Detach(NativeDbgProcess process)
        {
            int pid = process != null ? process.Id : throw new ArgumentNullException(nameof(process));
            if (!NativeMethods.DebugActiveProcessStop((uint)pid))
            {
                int lastWin32Error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException("Failed to detach to process " + (object)pid + "error=" + (object)lastWin32Error);
            }
            this.RemoveProcess(pid);
        }

        public NativeEvent WaitForDebugEvent(int timeout)
        {
            if (IntPtr.Size == 4)
            {
                DebugEvent32 pDebugEvent = new DebugEvent32();
                if (NativeMethods.WaitForDebugEvent32(ref pDebugEvent, timeout))
                    return NativeEvent.Build(this, ref pDebugEvent.header, ref pDebugEvent.union);
            }
            else
            {
                DebugEvent64 pDebugEvent = new DebugEvent64();
                if (NativeMethods.WaitForDebugEvent64(ref pDebugEvent, timeout))
                    return NativeEvent.Build(this, ref pDebugEvent.header, ref pDebugEvent.union);
            }
            return (NativeEvent)null;
        }

        public NativeEvent WaitForDebugEventInfinite()
        {
            if (this.m_processes.Count == 0)
                throw new InvalidOperationException("Pipeline is not debugging any processes. Waiting for a debug event will hang.");
            return this.WaitForDebugEvent(-1) ?? throw new InvalidOperationException("WaitForDebugEvent failed for non-timeout reason");
        }

        public void ContinueEvent(NativeEvent nativeEvent)
        {
            if (nativeEvent == null)
                throw new ArgumentNullException(nameof(nativeEvent));
            if (nativeEvent.ContinueStatus == NativeMethods.ContinueStatus.CONTINUED)
                throw new ArgumentException("event was already continued", nameof(nativeEvent));
            NativeDbgProcess nativeDbgProcess = nativeEvent.Pipeline == this ? nativeEvent.Process : throw new ArgumentException("event does not belong to this pipeline");
            nativeEvent.DoCleanupForContinue();
            if (!NativeMethods.ContinueDebugEvent((uint)nativeEvent.ProcessId, (uint)nativeEvent.ThreadId, nativeEvent.ContinueStatus))
            {
                int lastWin32Error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException("Continue failed on process " + (object)nativeEvent.ProcessId + " error=" + (object)lastWin32Error);
            }
            nativeEvent.ContinueStatus = NativeMethods.ContinueStatus.CONTINUED;
        }

        public void ContinueEvent(NativeEvent nativeEvent, bool bNotHandle)
        {
            if (nativeEvent == null)
                throw new ArgumentNullException(nameof(nativeEvent));
            if (nativeEvent.ContinueStatus == NativeMethods.ContinueStatus.CONTINUED)
                throw new ArgumentException("event was already continued", nameof(nativeEvent));
            NativeDbgProcess nativeDbgProcess = nativeEvent.Pipeline == this ? nativeEvent.Process : throw new ArgumentException("event does not belong to this pipeline");
            nativeEvent.DoCleanupForContinue();
            nativeEvent.ContinueStatus = !bNotHandle ? NativeMethods.ContinueStatus.DBG_CONTINUE : NativeMethods.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED;
            if (!NativeMethods.ContinueDebugEvent((uint)nativeEvent.ProcessId, (uint)nativeEvent.ThreadId, nativeEvent.ContinueStatus))
            {
                int lastWin32Error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException("Continue failed on process " + (object)nativeEvent.ProcessId + " error=" + (object)lastWin32Error);
            }
            nativeEvent.ContinueStatus = NativeMethods.ContinueStatus.CONTINUED;
        }

        public void Dispose()
        {
            foreach (NativeDbgProcess nativeDbgProcess in this.m_processes.Values)
                nativeDbgProcess.Dispose();
            GC.SuppressFinalize((object)true);
        }
    }

    public class NativeEvent
    {
        private NativeMethods.ContinueStatus m_ContinueStatus = NativeMethods.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED;
        internal DebugEventHeader m_header;
        public DebugEventUnion m_union;
        private NativePipeline m_pipeline;

        public NativePipeline Pipeline => this.m_pipeline;

        public NativeDebugEventCode EventCode => this.m_header.dwDebugEventCode;

        public int ThreadId => (int)this.m_header.dwThreadId;

        public int ProcessId => (int)this.m_header.dwProcessId;

        public NativeDbgProcess Process => this.m_pipeline.GetProcess(this.ProcessId);

        internal NativeMethods.ContinueStatus ContinueStatus
        {
            get => this.m_ContinueStatus;
            set => this.m_ContinueStatus = value;
        }

        internal NativeEvent(
          NativePipeline pipeline,
          ref DebugEventHeader header,
          ref DebugEventUnion union)
        {
            this.m_pipeline = pipeline;
            this.m_header = header;
            this.m_union = union;
        }

        internal static NativeEvent Build(
          NativePipeline pipeline,
          ref DebugEventHeader header,
          ref DebugEventUnion union)
        {
            pipeline.GetOrCreateProcess((int)header.dwProcessId);
            switch (header.dwDebugEventCode)
            {
                case NativeDebugEventCode.EXCEPTION_DEBUG_EVENT:
                    return (NativeEvent)new ExceptionNativeEvent(pipeline, ref header, ref union);
                case NativeDebugEventCode.CREATE_THREAD_DEBUG_EVENT:
                    return (NativeEvent)new CreateThreadNativeEvent(pipeline, ref header, ref union);
                case NativeDebugEventCode.CREATE_PROCESS_DEBUG_EVENT:
                    return (NativeEvent)new CreateProcessDebugEvent(pipeline, ref header, ref union);
                case NativeDebugEventCode.EXIT_THREAD_DEBUG_EVENT:
                    return (NativeEvent)new ExitThreadNativeEvent(pipeline, ref header, ref union);
                case NativeDebugEventCode.EXIT_PROCESS_DEBUG_EVENT:
                    return (NativeEvent)new ExitProcessDebugEvent(pipeline, ref header, ref union);
                case NativeDebugEventCode.LOAD_DLL_DEBUG_EVENT:
                    return (NativeEvent)new LoadDllNativeEvent(pipeline, ref header, ref union);
                case NativeDebugEventCode.UNLOAD_DLL_DEBUG_EVENT:
                    return (NativeEvent)new UnloadDllNativeEvent(pipeline, ref header, ref union);
                case NativeDebugEventCode.OUTPUT_DEBUG_STRING_EVENT:
                    return (NativeEvent)new OutputDebugStringNativeEvent(pipeline, ref header, ref union);
                default:
                    return new NativeEvent(pipeline, ref header, ref union);
            }
        }

        public override string ToString() => string.Format("Event Type:tid={0}, code={1}", (object)this.ThreadId, (object)this.EventCode);

        public virtual void DoCleanupForContinue()
        {
        }

        public INativeContext GetCurrentContext()
        {
            INativeContext context = NativeContextAllocator.Allocate();
            this.GetCurrentContext(context);
            return context;
        }

        public void GetCurrentContext(INativeContext context) => this.Process.GetThreadContext(this.ThreadId, context);

        public void WriteContext(INativeContext context)
        {
            IntPtr num = IntPtr.Zero;
            try
            {
                num = NativeMethods.OpenThread(ThreadAccess.THREAD_ALL_ACCESS, true, (uint)this.ThreadId);
                using (IContextDirectAccessor contextDirectAccessor = context.OpenForDirectAccess())
                    NativeMethods.SetThreadContext(num, contextDirectAccessor.RawBuffer);
            }
            finally
            {
                if (num != IntPtr.Zero)
                    NativeMethods.CloseHandle(num);
            }
        }
    }

    public abstract class DllBaseNativeEvent : NativeEvent
    {
        public NativeDbgModule Module => this.Process.LookupModule(this.BaseAddress);

        public abstract IntPtr BaseAddress { get; }

        internal DllBaseNativeEvent(
          NativePipeline pipeline,
          ref DebugEventHeader header,
          ref DebugEventUnion union)
          : base(pipeline, ref header, ref union)
        {
        }
    }

    public class NativeDbgProcess : IMemoryReader, IDisposable
    {
        private Dictionary<IntPtr, NativeDbgModule> m_modules = new Dictionary<IntPtr, NativeDbgModule>();
        private int m_id;
        private IntPtr m_handle;
        private bool m_fLoaderBreakpointReceived;

        public int Id => this.m_id;

        internal IntPtr Handle => this.m_handle;

        public IntPtr UnsafeHandle => this.m_handle;

        public bool IsInitialized => this.m_fLoaderBreakpointReceived;

        internal NativeDbgProcess(int id) => this.m_id = id;

        ~NativeDbgProcess() => this.Dispose(false);

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize((object)this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (this.m_handle != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(this.m_handle);
                this.m_handle = IntPtr.Zero;
            }
            if (!disposing)
                return;
            foreach (NativeDbgModule nativeDbgModule in this.m_modules.Values)
                nativeDbgModule.CloseHandle();
            this.m_modules.Clear();
        }

        public void TerminateProcess(int exitCode) => NativeMethods.TerminateProcess(this.m_handle, (uint)exitCode);

        public void Break()
        {
            if (!NativeMethods.DebugBreakProcess(this.m_handle))
                throw new InvalidOperationException("DebugBreak failed.");
        }

        public bool IsExited() => this.m_handle == IntPtr.Zero || NativeMethods.WaitForSingleObject(this.m_handle, 0U) == 0;

        public void InitHandle(IntPtr handle) => this.m_handle = handle;

        public void ClearHandle() => this.m_handle = IntPtr.Zero;

        public void ReadMemory(IntPtr address, byte[] buffer)
        {
            UIntPtr nSize = buffer != null ? new UIntPtr((uint)buffer.Length) : throw new ArgumentNullException(nameof(buffer));
            int lpNumberOfBytesRead;
            if (!NativeMethods.ReadProcessMemory(this.m_handle, address, buffer, nSize, out lpNumberOfBytesRead) || lpNumberOfBytesRead != buffer.Length)
                throw new ReadMemoryFailureException(address, buffer.Length);
        }

        public void HandleIfLoaderBreakpoint(NativeEvent nativeEvent)
        {
            if (this.m_fLoaderBreakpointReceived || !(nativeEvent is ExceptionNativeEvent) || ((ExceptionNativeEvent)nativeEvent).ExceptionCode != ExceptionCode.STATUS_BREAKPOINT)
                return;
            nativeEvent.ContinueStatus = NativeMethods.ContinueStatus.DBG_CONTINUE;
            this.m_fLoaderBreakpointReceived = true;
        }

        public NativeDbgModule LookupModule(IntPtr baseAddress)
        {
            NativeDbgModule nativeDbgModule;
            return !this.m_modules.TryGetValue(baseAddress, out nativeDbgModule) ? (NativeDbgModule)null : nativeDbgModule;
        }

        public NativeDbgModule FindModuleForAddress(IntPtr address)
        {
            foreach (NativeDbgModule nativeDbgModule in this.m_modules.Values)
            {
                long int64_1 = nativeDbgModule.BaseAddress.ToInt64();
                int size = nativeDbgModule.Size;
                long num = int64_1 + (long)size;
                long int64_2 = address.ToInt64();
                if (int64_2 >= int64_1 && int64_2 < num)
                    return nativeDbgModule;
            }
            return (NativeDbgModule)null;
        }

        internal void AddModule(NativeDbgModule module) => this.m_modules[module.BaseAddress] = module;

        internal void RemoveModule(IntPtr baseAddress) => this.m_modules.Remove(baseAddress);

        public INativeContext GetThreadContext(int threadId)
        {
            INativeContext context = NativeContextAllocator.Allocate();
            this.GetThreadContext(threadId, context);
            return context;
        }

        public void GetThreadContext(int threadId, INativeContext context)
        {
            IntPtr num = IntPtr.Zero;
            try
            {
                num = NativeMethods.OpenThread(ThreadAccess.THREAD_ALL_ACCESS, true, (uint)threadId);
                using (IContextDirectAccessor contextDirectAccessor = context.OpenForDirectAccess())
                    NativeMethods.GetThreadContext(num, contextDirectAccessor.RawBuffer);
            }
            finally
            {
                if (num != IntPtr.Zero)
                    NativeMethods.CloseHandle(num);
            }
        }
    }

    public class NativeDbgModule
    {
        private NativeDbgProcess m_process;
        private string m_name;
        private IntPtr m_baseAddress;
        private int m_size;
        private long m_FileSize;
        private IntPtr m_hFile;

        public NativeDbgProcess Process => this.m_process;

        public string Name => this.m_name;

        public IntPtr BaseAddress => this.m_baseAddress;

        public int Size
        {
            get
            {
                if (this.m_size == 0)
                {
                    uint countBytes = (uint)Marshal.SizeOf(typeof(ModuleInfo));
                    ModuleInfo lpmodinfo = new ModuleInfo();
                    if (NativeMethods.GetModuleInformation(this.Process.Handle, this.BaseAddress, out lpmodinfo, countBytes))
                        this.m_size = (int)lpmodinfo.SizeOfImage;
                }
                return this.m_size;
            }
        }

        public int FileSize
        {
            get
            {
                this.CalculateFileSize();
                return (int)this.m_FileSize;
            }
        }

        public NativeDbgModule(
          NativeDbgProcess process,
          string name,
          IntPtr baseAddress,
          IntPtr fileHandle)
        {
            this.m_name = name;
            this.m_baseAddress = baseAddress;
            this.m_hFile = fileHandle;
            this.m_FileSize = -1L;
            this.m_process = process;
        }

        protected void CalculateFileSize()
        {
            if (this.m_FileSize != -1L)
                return;
            this.m_FileSize = 0L;
            long lpFileSize;
            if (!(this.m_hFile != IntPtr.Zero) || !NativeMethods.GetFileSizeEx(this.m_hFile, out lpFileSize))
                return;
            this.m_FileSize = lpFileSize;
        }

        public void CloseHandle()
        {
            if (!(this.m_hFile != IntPtr.Zero))
                return;
            NativeMethods.CloseHandle(this.m_hFile);
            this.m_hFile = IntPtr.Zero;
        }
    }

    [CLSCompliant(true)]
    public static class NativeContextAllocator
    {
        private static NativeContextAllocator.AllocatorFunction s_fpAllocator;

        public static INativeContext Allocate()
        {
            if (NativeContextAllocator.s_fpAllocator == null)
                throw new InvalidOperationException("No default allocator set.");
            return NativeContextAllocator.s_fpAllocator();
        }

        public static void SetDefaultAllocator(NativeContextAllocator.AllocatorFunction fp) => NativeContextAllocator.s_fpAllocator = fp;

        public delegate INativeContext AllocatorFunction();
    }

    public class LoadDllNativeEvent : DllBaseNativeEvent
    {
        private string m_cachedImageName;

        protected IntPtr BaseAddressWorker => this.m_union.LoadDll.lpBaseOfDll;

        public override IntPtr BaseAddress => this.BaseAddressWorker;

        internal LoadDllNativeEvent(
          NativePipeline pipeline,
          ref DebugEventHeader header,
          ref DebugEventUnion union)
          : base(pipeline, ref header, ref union)
        {
            this.Process.AddModule(new NativeDbgModule(this.Process, this.ReadImageName(), this.BaseAddressWorker, union.LoadDll.hFile));
        }

        public string ReadImageName()
        {
            if (this.m_cachedImageName == null)
            {
                this.m_cachedImageName = this.m_union.LoadDll.ReadImageNameFromTarget((IMemoryReader)this.Process);
                if (this.m_cachedImageName == null)
                    this.m_cachedImageName = "(unknown)";
            }
            return this.m_cachedImageName;
        }

        public override string ToString() => string.Format("DLL Load:Address 0x{0}, {1}", (object)this.BaseAddress.ToString("x"), (object)this.ReadImageName());
    }

    public class ExitThreadNativeEvent : NativeEvent
    {
        public int ExitCode => (int)this.m_union.ExitThread.dwExitCode;

        internal ExitThreadNativeEvent(
          NativePipeline pipeline,
          ref DebugEventHeader header,
          ref DebugEventUnion union)
          : base(pipeline, ref header, ref union)
        {
        }
    }

    public class ExitProcessDebugEvent : NativeEvent
    {
        internal ExitProcessDebugEvent(
          NativePipeline pipeline,
          ref DebugEventHeader header,
          ref DebugEventUnion union)
          : base(pipeline, ref header, ref union)
        {
        }

        public override void DoCleanupForContinue()
        {
            this.Process.ClearHandle();
            this.Pipeline.RemoveProcess(this.ProcessId);
        }
    }

    public class ExceptionNativeEvent : NativeEvent
    {
        public ExceptionCode ExceptionCode => this.m_union.Exception.ExceptionRecord.ExceptionCode;

        public bool FirstChance => this.m_union.Exception.dwFirstChance > 0U;

        public IntPtr Address => this.m_union.Exception.ExceptionRecord.ExceptionAddress;

        internal ExceptionNativeEvent(
          NativePipeline pipeline,
          ref DebugEventHeader header,
          ref DebugEventUnion union)
          : base(pipeline, ref header, ref union)
        {
        }

        public void ClearException() => this.ContinueStatus = NativeMethods.ContinueStatus.DBG_CONTINUE;

        public override string ToString() => string.Format("Exception Event:Tid={3}, 0x{0:x}, {1}, address=0x{2}", (object)this.ExceptionCode, this.FirstChance ? (object)"first chance" : (object)"unhandled", (object)this.Address.ToString("x"), (object)this.ThreadId);
    }

    public class CreateProcessDebugEvent : NativeEvent
    {
        internal CreateProcessDebugEvent(
          NativePipeline pipeline,
          ref DebugEventHeader header,
          ref DebugEventUnion union)
          : base(pipeline, ref header, ref union)
        {
            this.Process.InitHandle(union.CreateProcess.hProcess);
            this.Process.AddModule(new NativeDbgModule(this.Process, "<main program>", union.CreateProcess.lpBaseOfImage, union.CreateProcess.hFile));
        }
    }

    public class CreateThreadNativeEvent : NativeEvent
    {
        internal CreateThreadNativeEvent(
          NativePipeline pipeline,
          ref DebugEventHeader header,
          ref DebugEventUnion union)
          : base(pipeline, ref header, ref union)
        {
        }
    }
}
