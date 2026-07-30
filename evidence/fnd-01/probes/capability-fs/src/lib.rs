//! Compile surface for the exact FND-01 capability-filesystem candidates.
//!
//! `open_dir_nofollow` and `OpenOptionsFollowExt::follow(No)` protect only
//! the final path component. FND-07 must retain the root capability and call
//! these helpers one component at a time; this probe deliberately rejects a
//! multicomponent argument rather than implying stronger library semantics.

#![forbid(unsafe_code)]

use std::{
    io,
    path::{Component, Path},
};

use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, File, Metadata, OpenOptions};

fn require_one_normal_component(component: &Path) -> io::Result<()> {
    let mut components = component.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected exactly one normal relative path component",
        )),
    }
}

/// Open exactly one directory component without following a final symlink.
pub fn open_dir_component_nofollow(root: &Dir, component: &Path) -> io::Result<Dir> {
    require_one_normal_component(component)?;
    root.open_dir_nofollow(component)
}

/// Open exactly one file component without following a final symlink.
pub fn open_file_component_nofollow(root: &Dir, component: &Path) -> io::Result<File> {
    require_one_normal_component(component)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    root.open_with(component, &options)
}

/// Exercise the cross-platform identity surface without asserting that its
/// 64-bit inode value is sufficient for Windows ReFS.
pub fn identity_projection(metadata: &Metadata) -> (u64, u64, u64) {
    (metadata.dev(), metadata.ino(), metadata.nlink())
}
