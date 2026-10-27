//! Process-wide protection for operations that hold secret transient buffers.
use std::{
    fs,
    path::{Component, Path},
};

/// Require non-dumpability, disabled core files and a fresh no-swap cgroup.
pub(crate) fn protect_secret_process() -> Result<(), ()> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|_| ())?;
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| ())?;
    let membership = fs::read_to_string("/proc/self/cgroup").map_err(|_| ())?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or(())?;
    let path = Path::new(relative);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(());
    }
    let root = Path::new("/sys/fs/cgroup").join(path.strip_prefix("/").map_err(|_| ())?);
    for name in ["memory.swap.max", "memory.swap.current"] {
        if fs::read_to_string(root.join(name)).map_err(|_| ())?.trim() != "0" {
            return Err(());
        }
    }
    Ok(())
}
