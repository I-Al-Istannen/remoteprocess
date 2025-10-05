//! This crate provides a cross platform way of querying information about other processes running
//! on the system. This let's you build profiling and debugging tools.
//!
//! Features:
//!
//! * Getting the process executable name and current working directory
//! * Listing all the threads in the process
//! * Suspending the execution of a process or thread
//! * Returning if a thread is running or not
//! * Getting a stack trace for a thread in the target process
//! * Resolve symbols for an address in the other process
//! * Copy memory from the other process (using the read_process_memory crate)
//!
//! This crate provides implementations for Linux, OSX and Windows. However this crate is still
//! very much in alpha stage, and the following caveats apply:
//!
//! * Stack unwinding only works on x86_64 processors right now, and is disabled for arm/x86
//! * the OSX stack unwinding code is very unstable and shouldn't be relied on
//! * Getting the cwd on windows returns incorrect results
//!
//! # Example
//!
//! ```rust,no_run
//! #[cfg(feature="unwind")]
//! fn get_backtrace(pid: remoteprocess::Pid) -> Result<(), remoteprocess::Error> {
//!     // Create a new handle to the process
//!     let process = remoteprocess::Process::new(pid)?;
//!     // Create a stack unwind object, and use it to get the stack for each thread
//!     let unwinder = process.unwinder()?;
//!     let symbolicator = process.symbolicator()?;
//!     for thread in process.threads()?.iter() {
//!         println!("Thread {} - {}", thread.id()?, if thread.active()? { "running" } else { "idle" });
//!
//!         // lock the thread to get a consistent snapshot (unwinding will fail otherwise)
//!         // Note: the thread will appear idle when locked, so we are calling
//!         // thread.active() before this
//!         let _lock = thread.lock()?;
//!
//!         // Iterate over the callstack for the current thread
//!         for ip in unwinder.cursor(&thread)? {
//!             let ip = ip?;
//!
//!             // Lookup the current stack frame containing a filename/function/linenumber etc
//!             // for the current address
//!             symbolicator.symbolicate(ip, true, &mut |sf| {
//!                 println!("\t{}", sf);
//!             })?;
//!         }
//!     }
//!     Ok(())
//! }
//! ```

#[cfg(target_os = "macos")]
mod osx;
#[cfg(target_os = "macos")]
pub use osx::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "freebsd")]
pub use freebsd::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[derive(Debug)]
pub enum Error {
    NoBinaryForAddress(u64),
    GoblinError(goblin::error::Error),
    IOError(std::io::Error),
    Other(String),
    #[cfg(use_libunwind)]
    LibunwindError(libunwind::Error),
    #[cfg(target_os = "linux")]
    NixError(nix::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::NoBinaryForAddress(addr) => {
                write!(
                    f,
                    "No binary found for address 0x{:016x}. Try reloading.",
                    addr
                )
            }
            Self::GoblinError(ref e) => e.fmt(f),
            Self::IOError(ref e) => e.fmt(f),
            Self::Other(ref e) => write!(f, "{}", e),
            #[cfg(use_libunwind)]
            Self::LibunwindError(ref e) => e.fmt(f),
            #[cfg(target_os = "linux")]
            Self::NixError(ref e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::GoblinError(ref e) => Some(e),
            Self::IOError(ref e) => Some(e),
            #[cfg(use_libunwind)]
            Self::LibunwindError(ref e) => Some(e),
            #[cfg(target_os = "linux")]
            Self::NixError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<goblin::error::Error> for Error {
    fn from(err: goblin::error::Error) -> Self {
        Self::GoblinError(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IOError(err)
    }
}

#[cfg(target_os = "linux")]
impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Self {
        Self::NixError(err)
    }
}

#[cfg(use_libunwind)]
impl From<libunwind::Error> for Error {
    fn from(err: libunwind::Error) -> Self {
        Self::LibunwindError(err)
    }
}

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub line: Option<u64>,
    pub filename: Option<String>,
    pub function: Option<String>,
    pub module: String,
    pub addr: u64,
}

impl std::fmt::Display for StackFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let function = self.function.as_deref().unwrap_or("?");
        if let Some(filename) = self.filename.as_ref() {
            write!(
                f,
                "0x{:016x} {} ({}:{})",
                self.addr,
                function,
                filename,
                self.line.unwrap_or(0)
            )
        } else {
            write!(f, "0x{:016x} {} ({})", self.addr, function, self.module)
        }
    }
}

pub trait ProcessMemory {
    /// Copies memory from another process into an already allocated
    /// byte buffer
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<(), Error>;

    /// Copies a series of bytes from another process. Main difference
    /// with 'read' is that this will allocate memory for you
    fn copy(&self, addr: usize, length: usize) -> Result<Vec<u8>, Error> {
        let mut data = vec![0; length];
        self.read(addr, &mut data)?;
        Ok(data)
    }

    /// Copies a structure from another process
    fn copy_struct<T: Copy>(&self, addr: usize) -> Result<T, Error> {
        let mut data = vec![0; size_of::<T>()];
        self.read(addr, &mut data)?;
        Ok(unsafe { std::ptr::read(data.as_ptr() as *const _) })
    }

    /// Given a pointer that points to a struct in another process, returns the struct
    fn copy_pointer<T: Copy>(&self, ptr: *const T) -> Result<T, Error> {
        self.copy_struct(ptr as usize)
    }

    /// Copies a series of bytes from another process into a vector of
    /// structures of type T.
    fn copy_vec<T: Copy>(&self, addr: usize, length: usize) -> Result<Vec<T>, Error> {
        let mut vec = self.copy(addr, length * size_of::<T>())?;
        let capacity = vec.capacity() / size_of::<T>();
        let ptr = vec.as_mut_ptr() as *mut T;
        std::mem::forget(vec);
        unsafe { Ok(Vec::from_raw_parts(ptr, capacity, capacity)) }
    }
}

#[doc(hidden)]
/// Mock for using ProcessMemory on the local process.
pub struct LocalProcess;
impl ProcessMemory for LocalProcess {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<(), Error> {
        unsafe {
            std::ptr::copy_nonoverlapping(addr as *mut u8, buf.as_mut_ptr(), buf.len());
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "freebsd"))]
#[doc(hidden)]
/// Filters pids to own include descendations of target_pid
fn filter_child_pids(
    target_pid: Pid,
    processes: &std::collections::HashMap<Pid, Pid>,
) -> Vec<(Pid, Pid)> {
    let mut ret = Vec::new();
    for (child, parent) in processes.iter() {
        let mut current = *parent;
        loop {
            if current == target_pid {
                ret.push((*child, *parent));
                break;
            }
            current = match processes.get(&current) {
                Some(pid) => {
                    if current == *pid {
                        break;
                    }
                    *pid
                }
                None => break,
            };
        }
    }
    ret
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[derive(Copy, Clone)]
    struct Point {
        x: i32,
        y: i64,
    }

    #[test]
    fn test_copy_pointer() {
        let original = Point { x: 15, y: 25 };
        let copy = LocalProcess.copy_pointer(&original).unwrap();
        assert_eq!(original.x, copy.x);
        assert_eq!(original.y, copy.y);
    }

    #[test]
    fn test_copy_struct() {
        let original = Point { x: 10, y: 20 };
        let copy: Point = LocalProcess
            .copy_struct(&original as *const Point as usize)
            .unwrap();
        assert_eq!(original.x, copy.x);
        assert_eq!(original.y, copy.y);
    }
}
